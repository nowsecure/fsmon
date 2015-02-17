/* ios-fsmon -- Copyright NowSecure 2015 - pancake@nowsecure.com  */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "fsmon.h"

static FileMonitor fm = {0};

static int callback(FileMonitor *fm, FileMonitorEvent *ev) {
	char path[4096];
	if (fm->child) {
		if (fm->pid) {
			if (ev->pid != fm->pid)
				if (ev->ppid != fm->pid)
					return 0;
		}
	} else {
		if (fm->pid) {
			if (ev->pid != fm->pid)
				return 0;
		}
	}
	if (fm->root && ev->file) {
		if (strncmp (ev->file, fm->root, strlen (fm->root)))
			return 0;
	}
	if (fm->link && ev->file) {
		if (!strncmp (ev->file, fm->link, strlen (fm->link)))
			return 0;
	}
	if (fm->proc && ev->proc) {
		if (!strstr (ev->proc, fm->proc))
			return 0;
	}
	if (fm->json) {
		printf ("{\"filename\":\"%s\",\"pid\":%d,"
			"\"uid\":%d,\"gid\":%d,", 
			ev->file, ev->pid, ev->uid, ev->gid);
		if (ev->inode) {
			printf ("\"inode\":%d,", ev->inode);
		}
		if (ev->tstamp) {
			printf ("\"timestamp\":%lld,", ev->tstamp);
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
		printf ("\"type\":\"%s\"},", fm_typestr (ev->type));
	} else {
		if (fm->fileonly) {
			const char *p = ev->file;
			for (p=p+strlen (p);p>ev->file; p--) {
				if (*p == '/')
					ev->file = p+1;
			}
		}
		if (ev->type == FSE_RENAME) {
			printf ("%s%s%s\t%d\t\"%s%s%s\"\t%s -> %s\n",
				fm_colorstr (ev->type), fm_typestr (ev->type), Color_RESET,
				ev->pid, 
				Color_MAGENTA, ev->proc, Color_RESET,
				ev->file, ev->newfile);
		} else {
			printf ("%s%s%s\t%d\t\"%s%s%s\"\t%s\n",
				fm_colorstr (ev->type), fm_typestr (ev->type), Color_RESET,
				ev->pid, 
				Color_MAGENTA, ev->proc, Color_RESET,
				ev->file);
		}
	}
	if (fm->link) {
		int i;
		char destination[1024];
		const char *source = ev->file;
		char *fname = strdup (ev->file);
		for (i=0;fname[i];i++) {
			if (fname[i]=='/') {
				fname[i] = '_';
			}
		}
		if (ev->newfile) {
			source = ev->newfile;
		}
		if (is_directory (source)) {
			eprintf ("[I] Directories not copied\n");
		} else {
			snprintf (destination, sizeof (destination),
				"%s/%s", fm->link, fname);
			if (!copy_file (source, destination)) {
				eprintf ("[E] Error copying %s\n", destination);
			}
		}
		free (fname);
	}
	return 0;
}

static void help (const char *argv0) {
	eprintf ("Usage: %s [-jc] [-a sec] [-b dir] [-p pid] [-P proc] [path]\n",
		argv0);
	eprintf (
		" -a [sec]  stop monitoring after N seconds (alarm)\n"
		" -b [dir]  backup files to DIR folder (EXPERIMENTAL)\n"
		" -c        follow children of -p PID\n"
		" -h        show this help\n"
		" -j        output in JSON format\n"
		" -f        show only filename (no path)\n"
		" -p [pid]  only show events from this pid\n"
		" -P [proc] events only from process name\n"
	);
}

static void control_c (int sig) {
	fm.stop = 1;
	fm_end (&fm);
}

int main (int argc, char **argv) {
	int c, ret = 0;

	while ((c = getopt (argc, argv, "a:chb:fjp:P:")) != -1) {
		switch (c) {
		case 'a':
			fm.alarm = atoi (optarg);
			if (fm.alarm <1) {
				eprintf ("Invalid alarm time\n");
				return 1;
			}
			break;
		case 'f':
			fm.fileonly = 1;
			break;
		case 'b':
			fm.link = optarg;
			break;
		case 'c':
			fm.child = 1;
			break;
		case 'h':
			help (argv[0]);
			return 0;
		case 'j':
			fm.json = 1;
			break;
		case 'P':
			fm.proc = optarg;
			break;
		case 'p':
			fm.pid = atoi (optarg);
			break;
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
		fm_loop (&fm, callback);
	} else {
		ret = 1;
	}
	if (fm.json) {
		printf ("{}]\n");
	}
	fm_end (&fm);
	return ret;
}
