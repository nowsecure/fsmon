/* fsmon -- MIT - Copyright NowSecure 2016-2020 - pancake@nowsecure.com  */

#if __linux__

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "fsmon.h"

/* INOTIFY */
static int fd = -1;
#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

static void fm_control_c(void) {
	if (fd != -1) {
		close (fd);
		fd = -1;
	}
}

/* inotify fallback */

typedef struct PidPath {
	int fd;
	char *path;
} PidPath;

static int skipevents = 0;
static int pidpathn = 0;
static PidPath* pidpaths = NULL;

static void setPathForFd(int fd, const char *path) {
	int last = pidpathn++;
	PidPath* tmp = realloc (pidpaths, pidpathn * sizeof (PidPath));
	if (tmp) {
		tmp[last].fd = fd;
		tmp[last].path = strdup (path);
		pidpaths = tmp;
		skipevents += 2;
	}
}

static bool invalidPathForFd(int fd) {
	int i;
	if (fd == -1) {
		return false;
	}
	for (i = 0; i < pidpathn; i++) {
		PidPath *pp = &pidpaths[i];
		if (pp->fd == fd) {
			close (pp->fd);
			pp->fd = -1;
			free (pp->path);
			pp->path = NULL;
			return true;
		}
	}
	return false;
}

static const char *getPathForFd(int fd) {
	size_t i;
	if (fd == -1) {
		return false;
	}
	for (i = 0; i < pidpathn; i++) {
		PidPath *pp = &pidpaths[i];
		if (pp->fd == fd) {
			return pp->path;
		}
	}
	return "";
}

static void freePathForFd(void) {
	size_t i;
	for (i = 0; i < pidpathn; i++) {
		PidPath *pp = &pidpaths[i];
		free (pp->path);
	}
	free (pidpaths);
	pidpaths = NULL;
	pidpathn = 0;
}

static bool parseEvent(FileMonitor *fm, struct inotify_event *ie, FileMonitorEvent *ev) {
	static char absfile[PATH_MAX];
	ev->type = FSE_INVALID;
	if (ie->mask & IN_ACCESS) {
		if (ie->mask & IN_ISDIR) {
			return false;
		}
		ev->type = FSE_STAT_CHANGED;
	} else if (ie->mask & IN_MODIFY) {
		ev->type = FSE_CONTENT_MODIFIED;
	} else if (ie->mask & IN_ATTRIB) {
		ev->type = FSE_STAT_CHANGED;
	} else if (ie->mask & IN_OPEN) {
		if (ie->mask & IN_ISDIR) {
			return false;
		}
		ev->type = FSE_OPEN;
	} else if (ie->mask & IN_CREATE) {
		ev->type = (ie->mask & IN_ISDIR)
			? FSE_CREATE_DIR
			: FSE_CREATE_FILE;
	} else if (ie->mask & IN_DELETE) {
		ev->type = FSE_DELETE;
	} else if (ie->mask & IN_DELETE_SELF) {
		ev->type = FSE_DELETE;
	} else if (ie->mask & IN_MOVE_SELF) {
		ev->type = FSE_RENAME;
	} else if (ie->mask & IN_MOVED_FROM) {
		ev->type = FSE_RENAME;
	} else if (ie->mask & IN_MOVED_TO) {
		// rename in the same directory
		ev->type = FSE_RENAME;
	} else if (ie->mask & IN_CLOSE) {
		ev->type = FSE_CLOSE;
	} else if (ie->mask & IN_CLOSE_NOWRITE) {
		ev->type = FSE_CLOSE;
	} else if (ie->mask & IN_CLOSE_WRITE) {
		ev->type = FSE_CLOSE_WRITABLE;
	} else if (ie->mask & IN_IGNORED) {
		ev->type = FSE_UNKNOWN;
		eprintf ("Warning: ignored event\n");
	} else if (ie->mask & IN_UNMOUNT) {
		ev->type = FSE_CLOSE_WRITABLE;
		eprintf ("Warning: filesystem was unmounted\n");
	} else if (ie->mask == IN_Q_OVERFLOW) {
		char cmd[512];
		snprintf (cmd, sizeof (cmd) - 1, "sysctl -w fs.inotify.max_queued_events=%d",
			max_queued_events);
		max_queued_events += 32768;
		eprintf ("Warning: inotify event queue is full.\n");
		eprintf ("Running: %s\n", cmd);
		system (cmd);
	} else {
		eprintf ("Unknown event 0x%04x\n", ie->mask);
	}
	#if 0
	if (i->mask & IN_IGNORED)       printf("IN_IGNORED ");
	if (i->mask & IN_ISDIR)         printf("IN_ISDIR ");
	if (i->mask & IN_Q_OVERFLOW)    printf("IN_Q_OVERFLOW ");
	if (i->mask & IN_UNMOUNT)       printf("IN_UNMOUNT ");
	#endif
	if (ie->len > 0) {
		if (*ie->name && fm->root && *fm->root) {
			const char *root = getPathForFd (ie->wd);
			snprintf (absfile, sizeof (absfile), "%s/%s", root, ie->name);
		} else {
			if (*ie->name) {
				snprintf (absfile, sizeof (absfile), "%s", ie->name);
			}
		}
		ev->file = absfile;
		if (ev->type == FSE_CREATE_DIR) {
			int wd = inotify_add_watch (fd, ev->file, IN_ALL_EVENTS);
			setPathForFd (wd, ev->file);
		}
	} else {
		ev->file = "."; // directory itself
	}
	return true;
}

static void fm_inotify_add_dirtree(int fd, const char *name) {
	struct dirent *entry;
	char path[1024];
	DIR *dir;

	if (!(dir = opendir (name))) {
		return;
	}
	if (!(entry = readdir (dir))) {
		return;
	}
	//eprintf ("Monitor %s\n", name);
	int wd = inotify_add_watch (fd, name, IN_ALL_EVENTS);
	setPathForFd (wd, name);
	do {
		if (entry->d_type == DT_DIR) {
			if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, "..")) {
				continue;
			}
			path[0] = 0;
			int len = snprintf (path, sizeof (path) - 1, "%s/%s", name, entry->d_name);
			if (len < 1) {
				path[sizeof (path) - 1] = 0;
			}
			path[len] = 0;
			fm_inotify_add_dirtree (fd, path);
		}
	} while ((entry = readdir (dir)));
	closedir (dir);
}

static bool fm_begin (FileMonitor *fm) {
	fm->control_c = fm_control_c;
	fd = inotify_init ();
	if (fd == -1) {
		perror ("inotify_init");
		return false;
	}
	fm_inotify_add_dirtree (fd, fm->root? fm->root: ".");
	return true;
}

static bool fm_loop (FileMonitor *fm, FileMonitorCallback cb) {
	char buf[BUF_LEN] __attribute__ ((aligned(8)));
	struct inotify_event *event;
	FileMonitorEvent ev = { 0 };
	int c;
	char *p;
	if (fd == -1) {
		return false;
	}
	for (; fm->running; ) {
		c = read (fd, buf, BUF_LEN);
		if (c < 1) {
			invalidPathForFd (fd);
			return false;
		}
		for (p = buf; p < buf + c; ) {
			event = (struct inotify_event *) p;
			if (parseEvent (fm, event, &ev)) {
				cb (fm, &ev);
			}
			memset (&ev, 0, sizeof (ev));
			p += sizeof (struct inotify_event) + event->len;
		}
	}
	return true;
}

static bool fm_end (FileMonitor *fm) {
	bool done = false;
	if (fd != -1) {
		close (fd);
		fd = -1;
		done = true;
	}
	freePathForFd ();
	return done;
}

FileMonitorBackend fmb_inotify = {
	.name = "inotify",
	.begin = fm_begin,
	.loop = fm_loop,
	.end = fm_end,
};

#endif
