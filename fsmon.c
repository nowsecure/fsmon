/* fsmon -- Copyright NowSecure 2015-2016 - pancake@nowsecure.com  */

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

#if __APPLE__
typedef struct __attribute__ ((__packed__)) {
	uint16_t type;
	uint16_t len;
	union {
		uint32_t u32;
		uint64_t u64;
		void *ptr;
	} val;
} FMEventStruct;

static int parseArg(FileMonitorEvent *ev, uint8_t *arg) {
	FMEventStruct *fme = (FMEventStruct *)arg;
	dev_t *dev;
	const char *str;

	switch (fme->type) {
	case 0:
		IF_FM_DEBUG eprintf ("kernel fs event ignored (LEN %d)\n", fme->len);
		return 2;
	case FSE_ARG_INT64: // This is a timestamp field on the FSEvent
		// Event IDs are monotonically increasing per system, even
		// across reboots and drives coming and going. They bear
		// no relation to any particular clock or timebase.
		ev->tstamp = fme->val.u64;
		IF_FM_DEBUG eprintf ("EventID: %lld\n", ev->tstamp);
		break;
	case FSE_ARG_STRING: // This is a filename, for move/rename (Type 3)
		str = ev->newfile = (const char *)&fme->val.ptr;
		IF_FM_DEBUG eprintf ("EventString: %s\n", (const char*)str);
		break;
	case FSE_ARG_DEV: // Block Device associated with the mounted fs
		dev = (dev_t *) &fme->val.u32;
		IF_FM_DEBUG eprintf ("EventDevice: %d,%d ", major(*dev), minor(*dev));
		ev->dev_major = major (*dev);
		ev->dev_minor = minor (*dev);
		break;
	case FSE_ARG_MODE:
		ev->mode = fme->val.u32;
		break;
	case FSE_ARG_INO:
		ev->inode = fme->val.u32;
		break;
	case FSE_ARG_UID: ev->uid = fme->val.u32;
		break;
	case FSE_ARG_GID: ev->gid = fme->val.u32;
		break;
	case FSE_ARG_PATH: // Not really used... Implement this later..
		IF_FM_DEBUG eprintf ("TODO: FSE_ARG_PATH\n");
		break;
	case FSE_ARG_FINFO: // Not handling this yet.. Not really used, either..
		IF_FM_DEBUG eprintf ("TODO: FSE_ARG_FINFO\n");
		break;
	case FSE_ARG_DONE:
		return -1;
	default:
		IF_FM_DEBUG eprintf ("(ARG of type %hd, len %hd)\n",
			fme->type, fme->len);
		return 0;
	}
	if (fme->len < 1) {
		return 0;
	}
	return 4 + fme->len;
}

static int fdsetup(int fd) {
	fsevent_clone_args clone_args = {0};
	int8_t events[FSE_MAX_EVENTS];
	int rc, cloned_fd = -1;

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
	uint8_t buf[FM_BUFSIZE] = {0};
	int rc, buf_idx = 0;

	for (;;) {
		if (buf_idx > 0) {
			memmove (buf, buf + buf_idx, (sizeof (buf) - buf_idx));
		}
		rc = read (fm->fd, buf + buf_idx, FM_BUFSIZE - buf_idx);
		if (rc < 1)
			break;
		buf_idx = 0;

		mustParseAgain:
		if (fm->stop)
			return 0;

		while (buf_idx < rc) {
			struct kfs_event_a *fse = (struct kfs_event_a *)
				(buf + buf_idx);
			if (fse->type == 0) {
				int skip = 0;
				for (skip = 0; skip<rc; skip++) {  
					if (buf_idx + 4 < sizeof (buf) && !memcmp (buf+buf_idx, "\x00\x00\x02\x00", 4)) {
						buf_idx += skip - 6;
						goto mustParseAgain;
					}
				}
			}

			ev.pid = fse->pid;
			ev.proc = getProcName (fse->pid, &ev.ppid);
			ev.type = fse->type;
#if 0
			printf ("%s (PID:%d) %s(%d)\n",
				getProcName (fse->pid), fse->pid,
				typeToString (fse->type), fse->type);
#endif
			buf_idx += sizeof (struct kfs_event_a);
			fse_arg = (struct kfs_event_arg *) &buf[buf_idx];
			ev.file = fse_arg->data;
			buf_idx += sizeof (kfs_event_arg) + fse_arg->pathlen ;

			int arg_len = parseArg (&ev, buf + buf_idx);
			if (arg_len == -1) {
				if (cb) {
					cb (fm, &ev);
				}
				memset (&ev, 0, sizeof (ev));
				arg_len = 2;
			}
			if (rc < buf_idx || arg_len < 3) {
				continue;
			}
			buf_idx += arg_len;
			while (arg_len >2) {
				arg_len = parseArg (&ev, buf + buf_idx);
				if (arg_len == -1) {
					if (cb) {
						cb (fm, &ev);
					}
					arg_len = 2;
					memset (&ev, 0, sizeof (ev));
				}
				buf_idx += arg_len;
			}
		}
		if (rc > buf_idx) {
			eprintf ("*** Warning: Some events may be lost\n");
		}
		buf_idx = 0;
	}
	return 0;
}

int fm_end (FileMonitor *fm) {
	if (fm->fd != -1)
		close (fm->fd);
	memset (fm, 0, sizeof (FileMonitor));
	return 0;
}

#elif __linux__

#warning Not yet supported on Linux

int fm_begin (FileMonitor *fm) {
}

int fm_end (FileMonitor *fm) {
}

#else
#error Unsupported platform
#endif
