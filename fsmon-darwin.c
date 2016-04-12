/* fsmon -- MIT - Copyright NowSecure 2015-2016 - pancake@nowsecure.com  */

#if __APPLE__
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include "fsmon.h"

#define R_MIN(x,y) (((x)>(y))?(y):(x))

typedef struct __attribute__ ((__packed__)) {
	uint16_t type;
	uint16_t len;
	union {
		uint32_t u32;
		uint64_t u64;
		void *ptr;
		uint16_t words[4];
	} val;
} FMEventStruct;

static void fsevent_free (FileMonitorEvent *ev) {
	memset (ev, 0, sizeof (*ev));
	ev->type = -1;
}

static int parse_event(FileMonitorEvent *ev, FMEventStruct *fme) {
	dev_t *dev;
	int len = fme->val.words[3];
	switch (fme->type) {
	case 0:
		break;
	case FSE_ARG_RAW:
	case FSE_ARG_VNODE:
	case FSE_ARG_INT32:
		/* not yet handled */
		break;
	case FSE_ARG_INT64: // This is a timestamp field on the FSEvent
		// Event IDs are monotonically increasing per system, even
		// across reboots and drives coming and going. They bear
		// no relation to any particular clock or timebase.
		ev->tstamp = fme->val.u64;
		break;
	case FSE_ARG_STRING: // This is a filename, for move/rename (Type 3)
		//ev->newfile = (const char *)(fme) + 12;
		break;
	case FSE_ARG_DEV: // Block Device associated with the mounted fs
		dev = (dev_t *) &fme->val.u32;
		ev->dev_major = major (*dev);
		ev->dev_minor = minor (*dev);
		break;
	case FSE_ARG_MODE:
		ev->mode = fme->val.u32;
		break;
	case FSE_ARG_INO:
		ev->inode = fme->val.u32;
		break;
	case FSE_ARG_UID:
		ev->uid = fme->val.u32;
		break;
	case FSE_ARG_GID: // 0xb // 11 // This shuold be ARG_STRING or ARG_PATH
		ev->gid = fme->val.u32;
		//ev->newfile = (const char *)(fme) + 12;
		break;
	case FSE_ARG_PATH:
		//ev->newfile = (const char *)(fme) + 12;
		break;
	case FSE_ARG_FINFO:
		// Not handling this yet.. Not really used, either..
		break;
	case FSE_ARG_DONE:
		return -1;
	case FSE_EVENTS_DROPPED: // 999 / 0x3e7
		/* do nothing */
		return 8;
	default:
		eprintf ("ERROR unknown type %d\n", fme->type);
		/* ERROR */
		return 0;
	}
	return len + sizeof (FMEventStruct);
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
	/* get extended info from events */
	if ((rc = ioctl (cloned_fd, FSEVENTS_WANT_EXTENDED_INFO, NULL)) < 0) {
		perror ("ioctl");
		close (cloned_fd);
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
		perror ("fdclone");
		return 0;
	}
	fm->fd = fd;
	return 1;
}

int fm_loop (FileMonitor *fm, FileMonitorCallback cb) {
	FileMonitorEvent ev = {0};
	uint8_t buf[FM_BUFSIZE] = {0};
	int arg_len, rc, buf_idx = 0, buf_end = -1;

	if (sizeof (FMEventStruct) != 12) {
		eprintf ("Invalid FMEventStruct, check your compiler\n");
		return 0;
	}
	for (;;) {
		int rewind = 0;
		if (buf_idx == buf_end) {
			buf_idx = 0;
		} else if (buf_idx > 0) {
			if (buf_idx > buf_end) {
				eprintf ("Overflow detected and corrected (%d, %d)\n", buf_idx, buf_end);
				buf_idx = 0;
			} else {
				memmove (buf, buf + buf_idx, (buf_end - buf_idx));
				rewind = buf_idx = (buf_end - buf_idx);
			}
		}
		if (buf_idx > FM_BUFSIZE) {
			eprintf ("Warning: Some data is lost in fsevents data read (%d, %d)\n", buf_idx, FM_BUFSIZE);
			buf_idx = 0;
		}
		memset (buf + buf_idx, 0x00, FM_BUFSIZE - buf_idx);
		rc = read (fm->fd, buf + buf_idx, FM_BUFSIZE - buf_idx);
		// hexdump (buf+buf_idx, rc, 0); //arg_len + 2, 0);
		if (rc < 1) {
			perror ("read");
			return 0;
		}
		buf_idx = 0;
		buf_end = buf_idx + rc;

		if (fm->stop)
			return 0;

		if (buf_end >= sizeof (buf))
			buf_end = sizeof (buf);
		while (buf_idx + 1 < buf_end) {
			FMEventStruct *fme = (FMEventStruct*) (buf + buf_idx);
			/* initialize on first set */
			if (ev.type == -1) {
				ev.type = fme->type;
				ev.pid = fme->val.u32;
				ev.proc = ev.proc = getProcName (ev.pid, &ev.ppid);
				ev.file = (const char *)buf + buf_idx + sizeof (FMEventStruct);
			}
			/* parse data packet */
			arg_len = parse_event (&ev, fme);
			if (arg_len == -1) {
				if (ev.pid && ev.type != -1 && cb) cb (fm, &ev);
				fsevent_free (&ev);
				arg_len = 2;
			} else if (arg_len < 1) {
				arg_len = sizeof (FMEventStruct);
			} else if (arg_len > (buf_end - buf_idx)) {
				arg_len = sizeof (FMEventStruct) + 2;
				eprintf ("Invalid length in fsevents data packet (%d, %d)\n",
					arg_len, buf_end - buf_idx);
			}
			buf_idx += arg_len;
		}
	}
	return 0;
}

int fm_end (FileMonitor *fm) {
	if (fm->fd != -1)
		close (fm->fd);
	memset (fm, 0, sizeof (FileMonitor));
	return 0;
}

#else
#error Unsupported platform
#endif
