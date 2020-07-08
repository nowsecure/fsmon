/* fsmon -- MIT - Copyright NowSecure 2015-2020 - pancake@nowsecure.com  */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include "fsmon.h"

static FileMonitor fm = { 0 };
static bool firstnode = true;
static bool colorful = true;

FileMonitorBackend *backends[] = {
#if __APPLE__
#if !TARGET_WATCHOS
	&fmb_fsevapi,
#endif
	&fmb_devfsev,
	&fmb_kqueue,
	&fmb_kdebug,
#else
	&fmb_inotify,
#if HAVE_FANOTIFY
	&fmb_fanotify,
#endif
#endif
	NULL
};

static void control_c(int sig) {
	fm.running = false;
}

static bool setup_signals() {
	bool res = true;
	struct sigaction int_handler = {
		.sa_handler = control_c
	};
	if (sigaction (SIGINT, &int_handler, 0) == -1) {
		eprintf ("Cannot setup the SIGINT handler\n");
		res = false;
	}
	fm.running = true;
	if (fm.alarm) {
		if (sigaction (SIGALRM, &int_handler, 0) == -1) {
			eprintf ("Cannot setup the SIGALRM handler.\n");
			res = false;
		}
		if (alarm (fm.alarm) != 0) {
			eprintf ("Warning: A previous alarm was found.\n");
			res = false;
		}
	}
	return res;
}

static uint64_t __sys_now(void) {
	uint64_t ret;
	struct timeval now;
	gettimeofday (&now, NULL);
	ret = now.tv_sec;
	ret <<= 20;
	ret |= now.tv_usec;
	//(sizeof (now.tv_sec) == 4
	return ret;
}

static bool callback(FileMonitor *fm, FileMonitorEvent *ev) {
	if (fm->child) {
		if (fm->pid && ev->pid != fm->pid) {
			if (ev->ppid != fm->pid) {
				return false;
			}
		}
	} else {
		if (fm->pid && ev->pid != fm->pid) {
			return false;
		}
	}
	if (fm->root && ev->file) {
		if (strncmp (ev->file, fm->root, strlen (fm->root))) {
			return false;
		}
	}
	if (fm->link && ev->file) {
		if (!strncmp (ev->file, fm->link, strlen (fm->link))) {
			return false;
		}
	}
	if (fm->proc && ev->proc) {
		if (!strstr (ev->proc, fm->proc)) {
			return false;
		}
	}
	if (fm->json || fm->jsonStream) {
		if (fm->jsonStream) {
			firstnode = true;
		}
		char *filename = fmu_jsonfilter (ev->file);
		printf ("%s{\"filename\":\"%s\",\"pid\":%d,"
			"\"uid\":%d,\"gid\":%d,", 
			(fm->jsonStream || firstnode)? "":",", filename, ev->pid, ev->uid, ev->gid);
		firstnode = false;
		free (filename);
		if (ev->inode) {
			printf ("\"inode\":%d,", ev->inode);
		}
		if (ev->tstamp) {
			uint64_t now = __sys_now();
			printf ("\"time\":%" PRId64 ",", now);
		}
		if (ev->tstamp) {
			printf ("\"timestamp\":%" PRId64 ",", ev->tstamp);
		}
		if (ev->inode) {
			printf ("\"dev\":{\"major\":%d,\"minor\":%d},",
				ev->dev_major, ev->dev_minor);
		}
		if (ev->mode) {
			printf ("\"mode\":%d,", ev->mode);
		}
		if (ev->ppid) {
			printf ("\"ppid\":%d,", ev->ppid);
		}
		if (ev->proc && *ev->proc) {
			char *proc = fmu_jsonfilter (ev->proc);
			printf ("\"proc\":\"%s\",", proc);
			free (proc);
		}
		if (ev->event && *ev->event) {
			char *event = fmu_jsonfilter (ev->event);
			printf ("\"event\":\"%s\",", event);
			free (event);
		}
		if (ev->newfile && *ev->newfile) {
			char *filename = fmu_jsonfilter (ev->newfile);
			printf ("\"newfile\":\"%s\",", filename);
			free (filename);
		}
		printf ("\"type\":\"%s\"}", fm_typestr (ev->type));
		if (fm->jsonStream) {
			printf ("\n");
			fflush (stdout);
		}
	} else {
		if (fm->fileonly && ev->file) {
			const char *p = ev->file;
			for (p = p + strlen (p); p > ev->file; p--) {
				if (*p == '/')
					ev->file = p + 1;
			}
		}
		const char *color_begin = colorful? fm_colorstr (ev->type): "";
		const char *color_begin2 = colorful? Color_MAGENTA: "";
		const char *color_end = colorful? Color_RESET: "";
		// TODO . show event type
		if (ev->type == FSE_RENAME) {
			printf ("%s%s%s\t%d\t\"%s%s%s\"\t%s -> %s\n",
				color_begin, fm_typestr (ev->type), color_end,
				ev->pid, color_begin2, ev->proc? ev->proc: "", color_end, ev->file,
				ev->newfile? ev->newfile: "?");
		} else {
			printf ("%s%s%s\t%d\t\"%s%s%s\"\t%s\n",
				color_begin, fm_typestr (ev->type), color_end,
				ev->pid, color_begin2, ev->proc? ev->proc: "", color_end, ev->file);
		}
	}
	if (fm->link) {
		size_t i;
		char dst[1024];
		const char *src = ev->file;
		char *fname = strdup (ev->file);
		if (!fname) {
			eprintf ("Cannot allocate ev->file\n");
			return false;
		}
		for (i = 0; fname[i]; i++) {
			if (fname[i] == '/') {
				fname[i] = '_';
			}
		}
		if (ev->newfile) {
			src = ev->newfile;
		}
		if (is_directory (src)) {
			eprintf ("[I] Directories not copied\n");
		} else {
			snprintf (dst, sizeof (dst), "%s/%s", fm->link, fname);
			if (!copy_file (src, dst)) {
				eprintf ("[E] Error copying %s\n", dst);
			}
		}
		free (fname);
	}
	return false;
}

static void help (const char *argv0) {
	eprintf ("Usage: %s [-Jjc] [-a sec] [-b dir] [-B name] [-p pid] [-P proc] [path]\n"
		" -a [sec]  stop monitoring after N seconds (alarm)\n"
		" -b [dir]  backup files to DIR folder (EXPERIMENTAL)\n"
		" -B [name] specify an alternative backend\n"
		" -c        follow children of -p PID\n"
		" -f        show only filename (no path)\n"
		" -h        show this help\n"
		" -j        output in JSON format\n"
		" -J        output in JSON stream format\n"
		" -n        do not use colors\n"
		" -L        list all filemonitor backends\n"
		" -p [pid]  only show events from this pid\n"
		" -P [proc] events only from process name\n"
		" -v        show version\n"
		" [path]    only get events from this path\n"
		, argv0);
}

static bool use_backend(const char *name) {
	size_t i;
	for (i = 0; backends[i]; i++) {
		if (!strcmp (backends[i]->name, name)) {
			fm.backend = *backends[i];
			return true;
		}
	}
	return false;
}

static void list_backends() {
	size_t i;
	for (i = 0; backends[i]; i++) {
		printf ("%s\n", backends[i]->name);
	}
}

int main (int argc, char **argv) {
	char *absroot[PATH_MAX];
	int c, ret = 0;
#if __APPLE__
	fm.backend = fmb_devfsev;
#else
	fm.backend = fmb_inotify;
#endif

	while ((c = getopt (argc, argv, "a:chb:B:d:fjJlLnp:P:v")) != -1) {
		switch (c) {
		case 'a':
			fm.alarm = atoi (optarg);
			if (fm.alarm < 1) {
				eprintf ("Invalid alarm time\n");
				return 1;
			}
			break;
		case 'b':
			fm.link = optarg;
			break;
		case 'B':
			use_backend (optarg);
			break;
		case 'c':
			fm.child = true;
			break;
		case 'h':
			help (argv[0]);
			return 0;
		case 'f':
			fm.fileonly = true;
			break;
		case 'j':
			fm.json = true;
			break;
		case 'J':
			fm.jsonStream = true;
			break;
		case 'l':
		case 'L':
			list_backends ();
			return 0;
		case 'n':
			colorful = false;
			break;
		case 'p':
			fm.pid = atoi (optarg);
			break;
		case 'P':
			fm.proc = optarg;
			break;
		case 'v':
			printf ("fsmon %s\n", FSMON_VERSION);
			return 0;
		}
	}
	if (optind < argc) {
		if (optind + 1 < argc) {
			eprintf ("Warning: Too many arguments passed, capturing events only from the first path.\n");
		}
		char * res = realpath (argv[optind], (char *)absroot);
		if (!res) {
			eprintf ("Invalid path\n");
			free (absroot);
			return 1;
		}
		fm.root = (const char *)absroot;
	}
	if (fm.child && !fm.pid) {
		eprintf ("-c requires -p\n");
		return 1;
	}
	if (fm.json && !fm.jsonStream) {
		printf ("[");
	}
	if (fm.backend.begin (&fm)) {
		(void)setup_signals ();
		fm.backend.loop (&fm, callback);
	} else {
		ret = 1;
	}
	if (fm.json && !fm.jsonStream) {
		printf ("]\n");
	}
	fflush (stdout);
	fm.backend.end (&fm);
	return ret;
}
