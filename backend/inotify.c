/* fsmon -- MIT - Copyright NowSecure 2016-2025 - pancake@nowsecure.com  */

#if __linux__

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <libgen.h>
#include <unistd.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "fsmon.h"

#define USE_LSOF 0

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

#if USE_LSOF
/* this is very slow, better not to enable it */
static void lsof(const char *filename) {
	DIR *d = opendir ("/proc");
	if (!d) {
		return;
	}
	struct dirent *entry, *entry2;
	while ((entry = readdir (d))) {
		int pid = atoi (entry->d_name);
		if (!pid) {
			continue;
		}
		if (pid < 500) {
			continue;
		}
		char file[128];
		snprintf (file, sizeof (file), "/proc/%d/fd", pid);
		DIR *d2 = opendir (file);
		if (d2) {
			char dest[PATH_MAX];
			while ((entry2 = readdir (d2))) {
				snprintf (file, sizeof (file), "/proc/%d/fd/%s", pid, entry2->d_name);
				ssize_t r = readlink (file, dest, sizeof (dest));
				if (r != -1) {
					dest[r] = 0;
					if (!strcmp (filename, dest)) {
						printf ("PID %d USE %s\n", pid, dest);
						closedir (d);
						closedir (d2);
						return;
					}
				}
			}
			closedir (d2);
		}
	}
	closedir (d);
}
#endif

static bool uidofpath(const char *str, FileMonitorEvent *ev) {
        struct stat buf = {0};
        if (!str || !*str) {
		return 0;
	}
        if (true) { // stat (str, &buf) == -1) {
		char d[PATH_MAX] = {0};
		strncpy (d, str, sizeof (d) - 1);
		d[PATH_MAX - 1] = 0;
		char *dn = dirname (d);
		if (dn) {
			if (stat (dn, &buf) == -1) {
				return false;
			}
		}
	}
	ev->uid = buf.st_uid;
	ev->gid = buf.st_gid;
	return true;
}

struct uidcache_t {
	int uid;
	int pid;
	char *name;
};

#define UIDCACHE_SIZE 1024

struct uidcache_t uidcache[UIDCACHE_SIZE] = {
	{0}
};

static bool add_uidcache(int uid, int pid, const char *name) {
	size_t i;
	for (i = 0; uidcache[i].name; i++) {
		// skip empty entries
	}
	if (i == UIDCACHE_SIZE - 1) {
		return false;
	}
	uidcache[i].uid = uid;
	uidcache[i].pid = pid;
	uidcache[i].name = strdup (name);
	return true;
}

static int pidofuid(int uid, FileMonitorEvent *ev) {
	static char static_name[128];
	if (uid == 0) {
		return 0;
	}
	size_t i;
	for (i = 0; uidcache[i].name; i++) {
		if (uid == uidcache[i].uid) {
			ev->proc = uidcache[i].name;
			ev->pid = uidcache[i].pid;
			return true;
		}
	}
	// stat /proc/*/cwd | grep uid == st_uid
	DIR *d = opendir ("/proc");
	struct dirent *entry;
	while ((entry = readdir (d))) {
		int pid = atoi (entry->d_name);
		if (pid == 0) {
			continue;
		}
		struct stat buf = {0};
		char str[64];
		snprintf (str, sizeof (str), "/proc/%d/task", pid);
		if (stat (str, &buf) == -1) {
			closedir (d);
			continue;
		}
		if (buf.st_uid == uid) {
			if (buf.st_uid != 0) {
				eprintf ("STAT %d %s%c", buf.st_uid, str, 10);
			}
			snprintf (str, sizeof (str), "/proc/%d/status", pid);
			FILE *f = fopen (str, "r");	
			if (!f) {
				closedir (d);
				continue;
			}
			char buf[1024];
			int res = fread (buf, 1, sizeof (buf) - 1, f);
			fclose (f);
			if (res == -1) {
				continue;
			}
			buf[res] = 0;
			char *name = strstr (buf, "Name:\t");
			if (name) {
				name += strlen ("Name:\t");
				char *nl = strchr (name, 10);
				if (nl) {
					*nl = 0;
					strncpy (static_name, name, sizeof (static_name) - 1);
					ev->proc = static_name;
					// eprintf ("APP %s%c", name, 10);
					add_uidcache (uid, pid, static_name);
				}
			}
			ev->proc = static_name;
			ev->pid = pid;
			closedir (d);
			return pid;
		}
	}
	return 0;
}

static bool parseEvent(FileMonitor *fm, struct inotify_event *ie, FileMonitorEvent *ev) {
	static int max_queued_events = 0x10000;
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
			} else {
				*absfile = 0;
			}
		}
		ev->file = absfile;
		if (ev->type == FSE_CREATE_DIR) {
			int wd = inotify_add_watch (fd, ev->file, IN_ALL_EVENTS);
			setPathForFd (wd, ev->file);
		}
		if (uidofpath (absfile, ev)) {
			pidofuid (ev->uid, ev);
		}
#if USE_LSOF
		lsof (absfile);
#endif
	} else {
		static char fdpath[64];
		snprintf (fdpath, sizeof (fdpath), "fd(%d)", ie->wd);
		ev->file = fdpath;
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
			const char *n = strcmp (name, "/")? name: "";
			int len = snprintf (path, sizeof (path) - 1, "%s/%s", n, entry->d_name);
			if (len < 1) {
				path[sizeof (path) - 1] = 0;
			}
			path[len] = 0;
			fm_inotify_add_dirtree (fd, path);
		}
	} while ((entry = readdir (dir)));
	closedir (dir);
}

static bool fm_begin(FileMonitor *fm) {
	fm->control_c = fm_control_c;
	fd = inotify_init ();
	if (fd == -1) {
		perror ("inotify_init");
		return false;
	}
	const char *root = fm->root ? fm->root: ".";
	fm_inotify_add_dirtree (fd, root);
	return true;
}

static bool fm_loop (FileMonitor *fm, FileMonitorCallback cb) {
	char buf[BUF_LEN] __attribute__ ((aligned(8)));
	struct inotify_event *event;
	FileMonitorEvent ev = { 0 };
	char absfile[PATH_MAX];
	int c;
	char *p;
	if (fd == -1) {
		return false;
	}
	int cookie = 0;
	for (; fm->running; ) {
		c = read (fd, buf, BUF_LEN);
		if (c < 1) {
			invalidPathForFd (fd);
			return false;
		}
		for (p = buf; p < buf + c; ) {
			event = (struct inotify_event *) p;
			if (parseEvent (fm, event, &ev)) {
				if (cookie) {
					cookie = 0;
					const char *a = ev.newfile;
					ev.newfile = ev.file;
					ev.file = a;
					cb (fm, &ev);
				} else {
					if (event->cookie) {
						cookie = event->cookie;
						const char *root = getPathForFd (event->wd);
						snprintf (absfile, sizeof (absfile), "%s/%s", root, event->name);
						ev.newfile = absfile;
					} else {
						cb (fm, &ev);
					}
				}
			}
			if (!cookie) {
				memset (&ev, 0, sizeof (ev));
			}
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
