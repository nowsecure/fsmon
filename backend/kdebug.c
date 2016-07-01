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

#define PRIVATE
#define __APPLE_PRIVATE
#include "kdebug/kdebug.c"

static bool fm_begin (FileMonitor *fm) {
	return kdebug_begin ();
}

static bool fm_loop (FileMonitor *fm, FileMonitorCallback cb) {
	kdebug_env (fm, cb);
	for (; fm->running; ) {
		/* read events, run callback */
		bool rc = kdebug_loop_once ();
		fflush (stdout);
	}
	return true;
}

static bool fm_end(FileMonitor *fm) {
	return kdebug_stop ();
	return false;
}

FileMonitorBackend fmb_kdebug = {
	.name = "kdebug",
	.begin = fm_begin,
	.loop = fm_loop,
	.end = fm_end,
};

#endif
