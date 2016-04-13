/* fsmon -- MIT - Copyright NowSecure 2015-2016 - pancake@nowsecure.com  */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include "fsmon.h"

static FileMonitor fm = {0};
static bool firstnode = true;

static bool callback(FileMonitor *fm, FileMonitorEvent *ev) {
	if (fm->child) {
		if (fm->pid) {
			if (ev->pid != fm->pid)
				if (ev->ppid != fm->pid)
					return false;
		}
	} else {
		if (fm->pid) {
			if (ev->pid != fm->pid)
				return false;
		}
	}
	if (fm->root && ev->file) {
		if (strncmp (ev->file, fm->root, strlen (fm->root)))
			return false;
	}
	if (fm->link && ev->file) {
		if (!strncmp (ev->file, fm->link, strlen (fm->link)))
			return false;
	}
	if (fm->proc && ev->proc) {
		if (!strstr (ev->proc, fm->proc))
			return false;
	}
	if (fm->json) {
		printf ("%s{\"filename\":\"%s\",\"pid\":%d,"
			"\"uid\":%d,\"gid\":%d,", 
			firstnode? "":",", ev->file, ev->pid, ev->uid, ev->gid);
		firstnode = false;
		if (ev->inode) {
			printf ("\"inode\":%d,", ev->inode);
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
			printf ("\"proc\":\"%s\",", ev->proc);
		}
		if (ev->newfile && *ev->newfile) {
			printf ("\"newfile\":\"%s\",", ev->newfile);
		}
		printf ("\"type\":\"%s\"}", fm_typestr (ev->type));
	} else {
		if (fm->fileonly && ev->file) {
			const char *p = ev->file;
			for (p = p + strlen (p); p > ev->file; p--) {
				if (*p == '/')
					ev->file = p + 1;
			}
		}
		if (ev->type == FSE_RENAME) {
			printf ("%s%s%s\t%d\t\"%s%s%s\"\t%s -> %s\n",
				fm_colorstr (ev->type), fm_typestr (ev->type), Color_RESET,
				ev->pid, Color_MAGENTA, ev->proc? ev->proc: "", Color_RESET, ev->file,
				ev->newfile);
		} else {
			printf ("%s%s%s\t%d\t\"%s%s%s\"\t%s\n",
				fm_colorstr (ev->type), fm_typestr (ev->type), Color_RESET,
				ev->pid, Color_MAGENTA, ev->proc? ev->proc: "", Color_RESET, ev->file);
		}
	}
	if (fm->link) {
		int i;
		char dst[1024];
		const char *src = ev->file;
		char *fname = strdup (ev->file);
		if (!fname) {
			eprintf ("Cannot allocate ev->file\n");
			return false;
		}
		for (i=0; fname[i]; i++) {
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
	eprintf ("Usage: %s [-jc] [-a sec] [-b dir] [-p pid] [-P proc] [path]\n"
		" -a [sec]  stop monitoring after N seconds (alarm)\n"
		" -b [dir]  backup files to DIR folder (EXPERIMENTAL)\n"
		" -c        follow children of -p PID\n"
		" -h        show this help\n"
		" -j        output in JSON format\n"
		" -f        show only filename (no path)\n"
		" -p [pid]  only show events from this pid\n"
		" -P [proc] events only from process name\n"
		" -v        show version\n"
		" [path]    only get events from this path\n"
		, argv0);
}

static void control_c (int sig) {
	fm.stop = true;
	if (fm.json) {
		printf ("]\n");
	}
	if (fm.control_c)
		fm.control_c ();
	fm_end (&fm);
}

int main (int argc, char **argv) {
	int c, ret = 0;

	while ((c = getopt (argc, argv, "a:chb:d:fjp:P:v")) != -1) {
		switch (c) {
		case 'a':
			fm.alarm = atoi (optarg);
			if (fm.alarm <1) {
				eprintf ("Invalid alarm time\n");
				return 1;
			}
			break;
		case 'b':
			fm.link = optarg;
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
	if (optind<argc) {
		fm.root = argv[optind];
	}
	if (fm.child && !fm.pid) {
		eprintf ("-c requires -p\n");
		return 1;
	}
	if (fm.json) {
		printf ("[");
	}
	if (fm_begin (&fm)) {
		signal (SIGINT, control_c);
		signal (SIGPIPE, exit);
		fm_loop (&fm, callback);
	} else {
		ret = 1;
	}
	if (fm.json) {
		printf ("]\n");
	}
	fm_end (&fm);
	return ret;
}
