/* fsmon -- MIT - Copyright NowSecure 2016 - pancake@nowsecure.com  */

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

#define KQUEUE_DEBUG 1

static bool fm_begin (FileMonitor *fm) {
	struct kevent direvent;
	int kq = kqueue ();
	int dirfd = open (fm->root, O_RDONLY);
	if (kq == -1) {
		return false;
	}

	EV_SET (&direvent, dirfd, EVFILT_VNODE, EV_ADD | EV_CLEAR | EV_ENABLE,
			NOTE_WRITE, 0, (void *)fm->root);

	kevent (kq, &direvent, 1, NULL, 0, NULL);
#if 0
	// Register interest in SIGINT with the queue.  The user data
	// is NULL, which is how we'll differentiate between
	// a directory-modification event and a SIGINT-received event.
	struct kevent sigevent;
	EV_SET (&sigevent, SIGINT, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, NULL);

	// kqueue event handling happens after the legacy API, so make
	// sure it doesn eat the signal before the kqueue can see it.
	signal (SIGINT, SIG_IGN);
	// Register the signal event.
	kevent (kq, &sigevent, 1, NULL, 0, NULL);
#endif
	fm->fd = kq;
	return true;
}

#if 0
    EVFILT_VNODE
       Takes a file descriptor as the identifier and the events to watch for
       in fflags, and returns when one or more of the requested events occurs
       on the descriptor.  The events to monitor are:

       NOTE_DELETE    unlink() was called on the file referenced by the de-
                      scriptor.

       NOTE_WRITE     A write occurred on the file referenced by the descrip-
                      tor.

       NOTE_EXTEND    The file referenced by the descriptor was extended.

       NOTE_ATTRIB    The file referenced by the descriptor had its attributes
                      changed.

       NOTE_LINK      The link count on the file changed.

       NOTE_RENAME    The file referenced by the descriptor was renamed.

#endif

static bool fm_loop (FileMonitor *fm, FileMonitorCallback cb) {
	struct kevent change;
	for (; fm->running; ) {
		if (kevent (fm->fd, NULL, 0, &change, 1, NULL) == -1) {
			break;
		}
#if KQUEUE_DEBUG
		printf ("ident: %ld\n", change.ident);
		printf ("flags: 0x%x\n", change.flags);
		printf ("fflags: 0x%x\n", change.fflags);
		printf ("data: %p\n", (void*)change.data);
		printf ("udata: %p\n", (void*)change.udata);
#endif
		// The signal event has NULL in the user data.  Check for that first.
		if (change.udata) {
			// udata is non-null, so it's the name of the directory
			printf ("%s\n", (char*)change.udata);
		} else {
			break;
		}
	}
	return 0;
}

static bool fm_end(FileMonitor *fm) {
	if (fm && fm->fd != -1) {
		close (fm->fd);
		fm->fd = -1;
		return true;
	}
	return false;
}

FileMonitorBackend fmb_kqueue = {
	.name = "kqueue",
	.begin = fm_begin,
	.loop = fm_loop,
	.end = fm_end,
};

#endif
