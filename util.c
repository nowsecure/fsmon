/* fsmon -- Copyright NowSecure 2015-2016 - pancake@nowsecure.com  */

#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <errno.h>
#include "fsmon.h"
/*
   static inline int isprint(unsigned char chr) {
   return 0x1F < chr && chr < 0x7F;
   }
 */
void hexdump(const uint8_t *buf, unsigned int len, int w) {
	unsigned int i, j;
	for (i = 0; i < len; i += w) {
		printf ("0x%08x: ", i);
		for (j = i; j < i + w; j++) {
			if (j<len) printf (j%2?"%02x ":"%02x", buf[j]);
			else printf (j%2?"   ":"  ");
		}
		printf(" ");
		for (j = i; j < i + w; j++)
			printf ("%c", isprint(buf[j])?buf[j]:'.');
		printf ("\n");
	}
}

#define TYPES_COUNT 11
// Utility functions
const char *fm_typestr(uint32_t type) {
#define __(x) [x]=#x
	const char *types[TYPES_COUNT] = {
		__ (FSE_CREATE_FILE),
		__ (FSE_DELETE),
		__ (FSE_STAT_CHANGED),
		__ (FSE_RENAME),
		__ (FSE_CONTENT_MODIFIED),
		__ (FSE_CREATE_DIR),
		__ (FSE_CHOWN),
		__ (FSE_EXCHANGE),
		__ (FSE_FINDER_INFO_CHANGED),
		__ (FSE_XATTR_MODIFIED),
		__ (FSE_XATTR_REMOVED),
	};
	if (type == FSE_OPEN)
		return "FSE_OPEN";
	return (type < TYPES_COUNT && types[type])? types[type]: "";
}

const char *fm_colorstr(uint32_t type) {
	const char *colors[TYPES_COUNT] = {
		Color_MAGENTA,// FSE_CREATE_FILE
		Color_RED,    // FSE_DELETE
		Color_YELLOW, // FSE_STAT_CHANGED
		Color_GREEN,  // FSE_RENAME
		Color_YELLOW, // FSE_CONTENT_MODIFIED
		Color_BLUE,   // FSE_CREATE_DIR
		Color_YELLOW, // FSE_CHOWN
		Color_GREEN,  // FSE_EXCHANGE
		Color_YELLOW, // FSE_FINDER_INFO_CHANGED
		Color_YELLOW, // FSE_XATTR_MODIFIED,
		Color_RED,    // FSE_XATTR_REMOVED,
	};
	if (type == FSE_OPEN)
		return Color_GREEN;
	return (type < TYPES_COUNT)? colors[type]: "";
}

const char *getProcName(int pid, int *ppid) {
	static char path[1024] = {0};
#if __APPLE__
	struct kinfo_proc * kinfo = (struct kinfo_proc*)&path;
	size_t len = 1000;
	int rc, mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = pid;

	if ((rc = sysctl (mib, 4, path, &len, NULL, 0)) < 0) {
		perror("trace facility failure, KERN_PROC_PID\n");
		exit (1);
	}

	if (ppid) *ppid = kinfo->kp_eproc.e_ppid;
	return kinfo->kp_proc.p_comm;
#elif __linux__
	char *p, *q;
	int fd;
	snprintf (path, sizeof (path), "/proc/%d/stat", pid);
	fd = open (path, O_RDONLY);
	if (fd == -1) {
		eprintf ("Cannot open '%s'\n", path);
		return NULL;
	}
	path[0] = 0;
	(void)read (fd, path, sizeof (path));
	path[sizeof (path) - 1] = 0;
	close (fd);
	p = strchr (path, '(');
	q = strchr (path, ')');

	if (p && q && p < q && q[1] && q[2]) {
		*q = 0;
		if (ppid) {
			char *r = strchr (q + 2, ' ');
			if (r) *ppid = atoi (r + 1);
		}
		return p + 1;
	}
	return NULL;
#else
#warning getProcName not supported for this platform
	return NULL;
#endif
}

bool is_directory (const char *str) {
        struct stat buf = {0};
        if (!str || !*str) return false;
        if (stat (str, &buf) == -1) return false;
        if ((S_IFBLK & buf.st_mode) == S_IFBLK) return false;
        return S_IFDIR == (S_IFDIR & buf.st_mode);
}

bool copy_file(const char *src, const char *dst) {
	char buf[4096];
	struct stat stat_src;
	int count, mode = 0640;
	int fd_src, fd_dst;
	fd_src = open (src, O_RDONLY);
	if (fd_src == -1) {
		perror ("open");
		return false;
	}
	if (!fstat (fd_src, &stat_src)) {
		mode = stat_src.st_mode;
	}
	fd_dst = open (dst, O_RDWR | O_CREAT | O_TRUNC, mode);
	if (fd_dst == -1) {
		close (fd_src);
		return false;
	}
	for (;;) {
		count = read (fd_src, buf, sizeof (buf));
		if (count < 1) {
			break;
		}
		(void) write (fd_dst, buf, count);
	}
	close (fd_src);
	close (fd_dst);
	return true;
}
