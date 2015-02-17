/* ios-fsmon -- Copyright NowSecure 2015 - pancake@nowsecure.com  */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include "fsmon.h"

static int parseArg(FileMonitorEvent *ev, uint8_t *arg) {
	uint16_t *argType = (uint16_t *) arg;
	uint16_t *argLen = (uint16_t*) (arg + 2);
	uint32_t *argVal = (uint32_t *) (arg + 4);
	uint64_t *argVal64 = (uint64_t *) (arg + 4);
	dev_t  *dev;
	char *str;

	switch (*argType) {
	case 0:
		IF_FM_DEBUG eprintf ("kernel fs event ignored (LEN %d)\n", *argLen);
		return 2;
	case FSE_ARG_INT64: // This is a timestamp field on the FSEvent
		IF_FM_DEBUG eprintf ("Arg64: %lld\n", *argVal64);
		ev->tstamp = *argVal64;
		break;
	case FSE_ARG_STRING: // This is a filename, for move/rename (Type 3)
		ev->newfile = (const char *)argVal;
		str = (char *)argVal;
		IF_FM_DEBUG eprintf ("FSE_ARG_STRING = %s\n", (char*)argVal);
		break;
	case FSE_ARG_DEV: // Block Device associated with the mounted fs
		dev = (dev_t *) argVal;
		IF_FM_DEBUG eprintf ("DEV: %d,%d ", major(*dev), minor(*dev));
		ev->dev_major = major (*dev);
		ev->dev_minor = minor (*dev);
		break;
	case FSE_ARG_MODE: ev->mode = *argVal; break;
	case FSE_ARG_INO: ev->inode = *argVal; break;
	case FSE_ARG_UID: ev->uid = *argVal; break;
	case FSE_ARG_GID: ev->gid = *argVal; break;
	case FSE_ARG_PATH: // Not really used... Implement this later..
		IF_FM_DEBUG eprintf ("TODO: FSE_ARG_PATH\n");
		break;
	case FSE_ARG_FINFO: // Not handling this yet.. Not really used, either..
		IF_FM_DEBUG eprintf ("TODO: FSE_ARG_FINFO\n");
		break;
	case FSE_ARG_DONE:
		return -1;
	default:
		IF_FM_DEBUG eprintf ("(ARG of type %hd, len %hd)\n", *argType, *argLen);
		return 0;
	}
	IF_FM_DEBUG eprintf ("RET (%d)\n", 4+*argLen);
	if (*argLen<1) {
		return 0;
	}
	return (4 + *argLen);
}

static int fdsetup(int fd) {
	fsevent_clone_args clone_args = {0};
	int8_t events[FSE_MAX_EVENTS];
	int i, rc, cloned_fd = -1;

	memset (events, FSE_REPORT, FSE_MAX_EVENTS); // FSE_IGNORE

	clone_args.fd = &cloned_fd; // This is the descriptor we get back
	clone_args.event_queue_depth = 10;
	clone_args.event_list = events;
	clone_args.num_events = FSE_MAX_EVENTS;

	rc = ioctl (fd, FSEVENTS_CLONE, &clone_args);
	close (fd);
	if (rc < 0) {
		perror ("ioctl");
		return -1;
	}
	return cloned_fd;
}

int fm_begin (FileMonitor *fm) {
	int fd;
	fm->fd = -1;
	fd = open (FM_DEV, O_RDONLY);
	if (fd == -1) {
		perror ("open "FM_DEV);
		return 0;
	}
	fd = fdsetup (fd);
	if (fd == -1) {
		eprintf ("fdclone");
		return 0;
	}
	fm->fd = fd;
	return 1;
}

int fm_loop (FileMonitor *fm, FileMonitorCallback cb) {
	FileMonitorEvent ev = {0};
	struct kfs_event_arg *fse_arg;
	unsigned short *arg_type;
	uint8_t buf[FM_BUFSIZE];
	int i, rc, offInBuf;

	mustReadAgain:
	memset (buf, 0, FM_BUFSIZE);
	for (;;) {
		rc = read (fm->fd, buf, FM_BUFSIZE);
		if (rc<1)
			break;
		offInBuf = 0;

		mustParseAgain:
		if (fm->stop)
			return 0;

		while (offInBuf < rc) {
			struct kfs_event_a *fse = (struct kfs_event_a *)
				(buf + offInBuf);
			// if (offInBuf) { printf ("Next event: %d\n", offInBuf);};
			if (fse->type == 0) {
				int skip = 0;
				for (skip = 0; skip<rc; skip++) {  
					if (!memcmp (buf+offInBuf, "\x00\x00\x02\x00", 4)) {
						printf ("DELTIFYING 6 bytes backward!\n");
						offInBuf += skip - 6;
						goto mustParseAgain;
					}
				}
#if FM_DEBUG
				hexdump (buf+offInBuf, rc-offInBuf, 16);
			} else {
				eprintf ("OKDUMP\n");
				//hexdump (buf+offInBuf, 16, 16);
#endif
			}

			ev.pid = fse->pid;
			ev.proc = getProcName (fse->pid, &ev.ppid);
			ev.type = fse->type;
#if 0
			printf ("%s (PID:%d) %s(%d)\n",
				getProcName (fse->pid), fse->pid,
			       typeToString (fse->type), fse->type);
#endif

			offInBuf += sizeof (struct kfs_event_a);
			fse_arg = (struct kfs_event_arg *) &buf[offInBuf];
			ev.file = fse_arg->data;
			offInBuf += sizeof (kfs_event_arg) + fse_arg->pathlen ;

			int arg_len = parseArg (&ev, buf + offInBuf);
			if (arg_len == -1) {
				if (cb) {
					cb (fm, &ev);
				}
				memset (&ev, 0, sizeof (ev));
				arg_len = 2;
			}

			if (rc <offInBuf) {
				// TODO: we are loosing some bytes here
				goto mustReadAgain;
			}
#if FM_DEBUG
			if (arg_len > (rc-offInBuf)) {
				// I NEED MORE 8 10 157 FOOD!!!
				printf ("\x1b[32mI NEED MORE %d %d %d FOOD!!!\x1b[0m\n",
					arg_len, rc, offInBuf);
			}
#endif
			if (arg_len<3) {
#if FM_DEBUG
				printf ("==> DROPPED %d %d bytes\n",
					offInBuf, rc);
				hexdump (buf+offInBuf, rc-offInBuf, 16);
#endif
				goto mustReadAgain;
#if 0
				memmove (buf, buf+offInBuf, (rc-offInBuf));
				rc = read (cloned_fd, buf, BUFSIZE-offInBuf);
				goto mustParseAgain;
#endif
				break;
			}
			offInBuf += arg_len;
			while (arg_len >2) {
				arg_len = parseArg (&ev, buf + offInBuf);
				if (arg_len == -1) {
					if (cb) {
						cb (fm, &ev);
					}
					arg_len = 2;
					memset (&ev, 0, sizeof (ev));
				}
				offInBuf += arg_len;
			}
		}
		if (rc > offInBuf) {
			eprintf ("***Warning: Some events may be lost\n");
		}
	}
	return 0;
}

int fm_end (FileMonitor *fm) {
	if (fm->fd>0)
		close (fm->fd);
	memset (fm, 0, sizeof (*fm));
	return 0;
}
