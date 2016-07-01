/* fsmon -- MIT - Copyright NowSecure 2016 - pancake@nowsecure.com  */

#if __linux__

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "fsmon.h"

/* available on 2.6.37 and android-21 */
/* kernel syscall */
#ifndef HAVE_FANOTIFY
#define HAVE_FANOTIFY 1
#endif

/* available on glibc, not in bionic */
/* libc api */
#ifndef HAVE_SYS_FANOTIFY
#define HAVE_SYS_FANOTIFY 1
#endif

#include <sys/inotify.h>
#if HAVE_FANOTIFY
#if HAVE_SYS_FANOTIFY
#include <sys/fanotify.h>
#else
#include <asm/unistd.h>
static int fanotify_init(unsigned int __flags, unsigned int __event_f_flags) {
	return syscall (__NR_fanotify_init, __flags, __event_f_flags);
}

static int fanotify_mark (int __fanotify_fd, unsigned int __flags,
	uint64_t __mask, int __dfd, const char *__pathname) {
	return syscall (__NR_fanotify_mark, __fanotify_fd, __flags, __mask, __dfd, __pathname);
}
#endif
#include <linux/fanotify.h>
#endif
 
/* INOTIFY */
static int fd = -1;
#define BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

#if HAVE_FANOTIFY
static int fan_fd = -1;
static fd_set rfds;
#endif

static void fm_control_c() {
	if (fd != -1) {
		close (fd);
		fd = -1;
	}
#if HAVE_FANOTIFY
	if (fan_fd != -1) {
		close (fan_fd);
		fan_fd = -1;
	}
#endif
}

/* fanotify fallback */
#if HAVE_FANOTIFY
static void usr1_handler(int sig __attribute__((unused)),
		siginfo_t *si __attribute__((unused)), void *unused __attribute__((unused))) {
	fanotify_mark (fan_fd, FAN_MARK_FLUSH, 0, 0, NULL);
}

static int handle_perm(int fan_fd, struct fanotify_event_metadata *metadata) {
	struct fanotify_response response_struct;
	int ret;
	response_struct.fd = metadata->fd;
	response_struct.response = FAN_ALLOW;
	ret = write (fan_fd, &response_struct, sizeof(response_struct));
	return (ret<0)? ret: 0;
}

static bool parseFaEvent(FileMonitor *fm, struct fanotify_event_metadata *metadata, FileMonitorEvent *ev) {
	char path[PATH_MAX];
	int path_len;

	if (metadata->fd >= 0) {
		sprintf (path, "/proc/self/fd/%d", metadata->fd);
		path_len = readlink (path, path, sizeof(path)-1);
		if (path_len < 0)
			return false;
		path[path_len] = '\0';
		//printf ("%s:", path);
	} else strcpy (path, ".");

	ev->file = path;
	ev->pid = metadata->pid;
	ev->proc = get_proc_name (ev->pid, &ev->ppid);
	if (metadata->mask & FAN_ACCESS) {
		ev->type = FSE_STAT_CHANGED;
	}
	if (metadata->mask & FAN_OPEN) ev->type = FSE_OPEN;
	if (metadata->mask & FAN_MODIFY) ev->type = FSE_CONTENT_MODIFIED;
	if (metadata->mask & FAN_CLOSE) {
		if (metadata->mask & FAN_CLOSE_WRITE) {
			ev->type = FSE_CREATE_FILE; // create
		}
		if (metadata->mask & FAN_CLOSE_NOWRITE) {
			ev->type = FSE_STAT_CHANGED; // close
		}
	}
	if (metadata->mask & FAN_OPEN_PERM) {
		ev->type = FSE_OPEN;
	}
	if (metadata->mask & FAN_ACCESS_PERM) {
		ev->type = FSE_STAT_CHANGED;
	}
	if (metadata->mask & FAN_ALL_PERM_EVENTS) {
		if (handle_perm (fan_fd, metadata)) {
			return false;
		}
	}
	return true;
}

static int fa_begin(FileMonitor *fm) {
	uint64_t fan_mask = FAN_OPEN | FAN_CLOSE | FAN_ACCESS | FAN_MODIFY;
	unsigned int mark_flags = FAN_MARK_ADD, init_flags = 0;
	struct sigaction sa;

	//mark_flags |= FAN_MARK_REMOVE;
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sigemptyset (&sa.sa_mask);
	sa.sa_sigaction = usr1_handler;

	if (sigaction (SIGUSR1, &sa, NULL) == -1) {
		eprintf ("Cannot set SIGUSR1 signal handler\n");
		goto fail;
	}

	fan_mask |= FAN_ONDIR;
	fan_mask |= FAN_EVENT_ON_CHILD;
	mark_flags |= FAN_MARK_MOUNT; // walk into subdirectories

	init_flags |= (fan_mask & FAN_ALL_PERM_EVENTS)?
		FAN_CLASS_CONTENT: FAN_CLASS_NOTIF;

	if (!fm->root) {
		fm->root = "/";
	}

	fan_fd = fanotify_init (init_flags, O_RDONLY); // | O_LARGEFILE);
	if (fan_fd < 0)
		goto fail;

	if (fanotify_mark (fan_fd, mark_flags, fan_mask, AT_FDCWD, fm->root) != 0) {
		perror("fanotify_mark");
		return -1;
	}

	FD_ZERO (&rfds);
	FD_SET (fan_fd, &rfds);
	return 1;
fail:
	perror ("fanotify");
	return 0;
}

static bool fa_loop (FileMonitor *fm, FileMonitorCallback cb) {
	FileMonitorEvent ev = {0};
	char buf[4096];
	ssize_t len;

	while (select (fan_fd+1, &rfds, NULL, NULL, NULL) < 0) {
		if (errno != EINTR || !fm->running)
			goto fail;
	}

	while ((len = read (fan_fd, buf, sizeof (buf))) > 0) {
		struct fanotify_event_metadata *metadata;
		if (!fm->running || fan_fd == -1)
			break;
		metadata = (void *)buf;
		while (FAN_EVENT_OK (metadata, len)) {
			if (metadata->vers < 2) {
				eprintf ("Kernel fanotify version too old\n");
				goto fail;
			}
			if (!parseFaEvent (fm, metadata, &ev))
				goto fail;
			if (ev.type != -1) cb (fm, &ev);
			memset (&ev, 0, sizeof (ev));
			if (metadata->fd >= 0 && close (metadata->fd) != 0)
				goto fail;
			metadata = FAN_EVENT_NEXT (metadata, len);
		}
		while (select (fan_fd + 1, &rfds, NULL, NULL, NULL) < 0)
			if (errno != EINTR || !fm->running)
				goto fail;
	}
	if (len < 0)
		goto fail;
	return true;
fail:
	perror ("fanotify_loop");
	return false;
}
#endif

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
	int i;
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

static void freePathForFd() {
	free (pidpaths);
	pidpaths = NULL;
	pidpathn = 0;
}

static void parseEvent(FileMonitor *fm, struct inotify_event *ie, FileMonitorEvent *ev) {
	static char absfile[PATH_MAX];
	ev->type = FSE_INVALID;
	if (ie->mask & IN_ACCESS) {
		if (ie->mask & IN_ISDIR) {
			return;
		}
		ev->type = FSE_STAT_CHANGED;
	} else if (ie->mask & IN_MODIFY) {
		ev->type = FSE_CONTENT_MODIFIED;
	} else if (ie->mask & IN_ATTRIB) {
		ev->type = FSE_STAT_CHANGED;
	} else if (ie->mask & IN_OPEN) {
		if (ie->mask & IN_ISDIR) {
			return;
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
		ev->type = FSE_RENAME;
	}
	#if 0
	if (i->mask & IN_IGNORED)       printf("IN_IGNORED ");
	if (i->mask & IN_ISDIR)         printf("IN_ISDIR ");
	if (i->mask & IN_Q_OVERFLOW)    printf("IN_Q_OVERFLOW ");
	if (i->mask & IN_UNMOUNT)       printf("IN_UNMOUNT ");
	#endif
	if (ie->len > 0) {
		if (ie->name && fm->root && *fm->root) {
			const char *root = getPathForFd (ie->wd);
			snprintf (absfile, sizeof (absfile), "%s/%s", root, ie->name);
		} else {
			if (ie->name) {
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
#if HAVE_FANOTIFY
	int rc = fa_begin (fm);
	if (rc) {
		return (rc == 1);
	}
#endif
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
#if HAVE_FANOTIFY
	if (fan_fd != -1 && fd == -1) {
		return fa_loop (fm, cb);
	}
#endif
	for (; fm->running; ) {
		c = read (fd, buf, BUF_LEN);
		if (c < 1) {
			invalidPathForFd (fd);
			return 0;
		}
		for (p = buf; p < buf + c; ) {
			event = (struct inotify_event *) p;
			parseEvent (fm, event, &ev);
			if (ev.type != -1 && ev.file) {
				cb (fm, &ev);
			}
			memset (&ev, 0, sizeof (ev));
			p += sizeof (struct inotify_event) + event->len;
		}
	}
	return true;
}

static bool fm_end (FileMonitor *fm) {
#define FMCLOSE(x) \
	if (x != -1) { \
		close (x); \
		x = -1; \
		done = true; \
	}

	bool done = false;
#if HAVE_FANOTIFY
	FMCLOSE (fan_fd);
#endif
	FMCLOSE (fd);
	freePathForFd ();
	return done;
}

FileMonitorBackend fmb_inotify = {
	.name = "inotify/fanotify",
	.begin = fm_begin,
	.loop = fm_loop,
	.end = fm_end,
};

#endif
