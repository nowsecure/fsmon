/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 * Copyright (c) 2016 NowSecure. by Sergi Alvarez <salvarez@nowsecure.com>
 * 
 * Changes:
 * --------
 * - Increase buffer size to avoid overruns on heavy system load
 * - Remove all code not related to file-system
 * - Refactor, simplify and cleanup
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <strings.h>
//#include <nlist.h>
#include <fcntl.h>
#include <aio.h>
#include <string.h>
#include <dirent.h>
//#include <libc.h>
#include <termios.h>
#include <errno.h>
#include <err.h>

#define eprintf(x,y...) fprintf(stderr,x,##y)
#define dprintf(x,y...) // fprintf(stderr,x,##y)

#include <sys/types.h>
#undef MAXCOMLEN
#define MAXCOMLEN 64
#include <sys/param.h>
#undef MAXCOMLEN
#define MAXCOMLEN 64
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
//#include <sys/disk.h>
#include <sys/file.h>
#include "kdebug.h"

bool kdebug_loop_once();

#define KDBG_TYPEFILTER_BITMAP_SIZE	        ( (256 * 256) / 8 )

/* The Kernel Debug Sub Classes for File System (DBG_FSYSTEM) */
#define DBG_FSRW      1       /* reads and writes to the filesystem */
#define DBG_DKRW      2       /* reads and writes to the disk */
#define DBG_FSVN      3       /* vnode operations (inc. locking/unlocking) */
#define DBG_FSLOOOKUP 4       /* namei and other lookup-related operations */
#define DBG_JOURNAL   5       /* journaling operations */
#define DBG_IOCTL     6       /* ioctl to the disk */
#define DBG_BOOTCACHE 7       /* bootcache operations */
#define DBG_HFS       8       /* HFS-specific events; see bsd/hfs/hfs_kdebug.h */
#define DBG_EXFAT     0xE     /* ExFAT-specific events; see the exfat project */
#define DBG_MSDOS     0xF     /* FAT-specific events; see the msdosfs project */
#define DBG_ACFS      0x10    /* Xsan-specific events; see the XsanFS project */
#define DBG_THROTTLE  0x11    /* I/O Throttling events */	
#define DBG_CONTENT_PROT 0xCF /* Content Protection Events: see bsd/sys/cprotect.h */

/* The Kernel Debug Sub Classes for BSD */
#define DBG_BSD_PROC		0x01	/* process/signals related */
#define DBG_BSD_MEMSTAT		0x02	/* memorystatus / jetsam operations */
#define	DBG_BSD_EXCP_SC		0x0C	/* System Calls */
#define	DBG_BSD_AIO		0x0D	/* aio (POSIX async IO) */
#define DBG_BSD_SC_EXTENDED_INFO 0x0E	/* System Calls, extended info */
#define DBG_BSD_SC_EXTENDED_INFO2 0x0F	/* System Calls, extended info */

/* The Function qualifiers  */
#define DBG_FUNC_START		1
#define DBG_FUNC_END		2
#define DBG_FUNC_NONE		0

#define DBG_CS_IO	0

/* The Kernel Debug Classes  */
#define DBG_MACH 1
#define DBG_FSYSTEM 3
#define DBG_BSD 4
#define DBG_IOKIT 5
#define DBG_DRIVERS 6
#define DBG_TRACE  7
#define DBG_CORESTORAGE 10

#define NUMPARMS 23
#define PATHLENGTH (NUMPARMS*sizeof(uintptr_t))

#define MAX_PATHNAMES		3
#define MAX_SCALL_PATHNAMES	2

static volatile bool running = true;
typedef struct th_info *th_info_t;

struct lookup {
	uintptr_t pathname[NUMPARMS + 1];	/* add room for null terminator */
};

struct th_info {
	th_info_t next;
	uintptr_t thread;
	uintptr_t child_thread;
	int pid;
	int type;
	int arg1;
	int arg2;
	int arg3;
	int arg4;
	int arg5;
	int arg6;
	int arg7;
	int arg8;
	double stime;
	uint64_t vnodeid;
	char *nameptr;
	uintptr_t *pathptr;
	int pn_scall_index;
	int pn_work_index;
	struct lookup lookups[MAX_PATHNAMES];
};

typedef struct threadmap * threadmap_t;

struct threadmap {
	threadmap_t tm_next;
	int tm_pid;
	uintptr_t tm_thread;
	unsigned int tm_setsize;	/* this is a bit count */
	unsigned long *tm_setptr;	/* file descripter bitmap */
	char tm_command[MAXCOMLEN + 1];
};

typedef struct vnode_info * vnode_info_t;

struct vnode_info {
	vnode_info_t	vn_next;
	uint64_t	vn_id;
	char vn_pathname[4096]; //NUMPARMS + 1];
};

#if 0
typedef struct meta_info * meta_info_t;

struct meta_info {
	meta_info_t     m_next;
	uint64_t        m_blkno;
	char            *m_nameptr;
};
#endif

#define HASH_SIZE       1024
#define HASH_MASK       (HASH_SIZE - 1)

th_info_t th_info_hash[HASH_SIZE];
th_info_t th_info_freelist;

threadmap_t threadmap_hash[HASH_SIZE];
threadmap_t threadmap_freelist;

#define VN_HASH_SHIFT   3
#define VN_HASH_SIZE	16384
#define VN_HASH_MASK	(VN_HASH_SIZE - 1)

static FileMonitor *fm = NULL;
static FileMonitorCallback cb = NULL;

void kdebug_env(FileMonitor *_fm, FileMonitorCallback _cb) {
	fm=_fm;
	cb=_cb;
}

static vnode_info_t vn_info_hash[VN_HASH_SIZE];
#if 0
static meta_info_t m_info_hash[VN_HASH_SIZE];
#endif

static bool need_new_map = true;

static int  one_good_pid = 0;    /* Used to fail gracefully when bad pids given */
static int  select_pid_mode = 0;  /* Flag set indicates that output is restricted */

/*
 * Network only or filesystem only output filter
 * Default of zero means report all activity - no filtering
 */
#define FILESYS_FILTER    0x01
#define NETWORK_FILTER    0x02
#define EXEC_FILTER	  0x08
#define PATHNAME_FILTER	  0x10
#define DISKIO_FILTER	0x20
#define DEFAULT_DO_NOT_FILTER  0x00

#define CLASS_MASK 0xff000000
#define CSC_MASK 0xffff0000
#define BSC_INDEX(type)	((type >> 2) & 0x3fff)

#define TRACE_DATA_NEWTHREAD   0x07000004
#define TRACE_DATA_EXEC        0x07000008
#define TRACE_STRING_NEWTHREAD 0x07010004
#define TRACE_STRING_EXEC      0x07010008

#define MACH_vmfault    0x01300008
#define MACH_pageout    0x01300004
#define MACH_sched      0x01400000
#define MACH_stkhandoff 0x01400008
#define MACH_idle	0x01400024
#define VFS_LOOKUP      0x03010090
#define VFS_ALIAS_VP    0x03010094

#define BSC_thread_terminate    0x040c05a4

#define HFS_update	     0x3018000
#define HFS_modify_block_end 0x3018004

#define Throttled	0x3010184
#define SPEC_ioctl	0x3060000
// #define SPEC_unmap_info	0x3060004
#define proc_exit	0x4010004
#define MSC_map_fd   0x010c00ac

#define BSC_BASE     0x040C0000
#define MSC_BASE     0x010C0000

#define BSC_exit		0x040C0004
#define BSC_fork		0x040C0008
#define BSC_read		0x040C000C
#define BSC_write		0x040C0010
#define BSC_open		0x040C0014
#define BSC_old_creat		0x040C0020
#define BSC_close		0x040C0018
#define BSC_link		0x040C0024
#define BSC_unlink		0x040C0028
#define BSC_chdir		0x040c0030
#define BSC_fchdir		0x040c0034
#define BSC_mknod		0x040C0038
#define BSC_chmod		0x040C003C
#define BSC_chown		0x040C0040
#define BSC_getfsstat		0x040C0048
#define BSC_access		0x040C0084
#define BSC_chflags		0x040C0088
#define BSC_fchflags		0x040C008C
#define BSC_sync		0x040C0090
#define BSC_dup			0x040C00A4
#define BSC_ioctl		0x040C00D8
#define BSC_revoke		0x040C00E0
#define BSC_symlink		0x040C00E4	
#define BSC_readlink		0x040C00E8
#define BSC_execve		0x040C00EC
#define BSC_umask		0x040C00F0
#define BSC_chroot		0x040C00F4
#define BSC_msync		0x040C0104
#define BSC_dup2		0x040C0168
#define BSC_fcntl		0x040C0170
#define BSC_fsync		0x040C017C	
#define BSC_readv		0x040C01E0	
#define BSC_writev		0x040C01E4	
#define BSC_fchown		0x040C01EC	
#define BSC_fchmod		0x040C01F0	
#define BSC_rename		0x040C0200
#define BSC_flock		0x040C020C
#define BSC_mkfifo		0x040C0210	
#define BSC_mkdir		0x040C0220	
#define BSC_rmdir		0x040C0224
#define BSC_utimes		0x040C0228
#define BSC_futimes		0x040C022C
#define BSC_pread		0x040C0264
#define BSC_pwrite		0x040C0268
#define BSC_statfs		0x040C0274	
#define BSC_fstatfs		0x040C0278
#define BSC_unmount	        0x040C027C
#define BSC_mount	        0x040C029C
#define BSC_fdatasync		0x040C02EC
#define BSC_stat		0x040C02F0	
#define BSC_fstat		0x040C02F4	
#define BSC_lstat		0x040C02F8	
#define BSC_pathconf		0x040C02FC	
#define BSC_fpathconf		0x040C0300
#define BSC_getdirentries	0x040C0310
#define BSC_mmap		0x040c0314
#define BSC_lseek		0x040c031c
#define BSC_truncate		0x040C0320
#define BSC_ftruncate   	0x040C0324
#define BSC_undelete		0x040C0334
#define BSC_open_dprotected_np 	0x040C0360	
#define BSC_getattrlist 	0x040C0370	
#define BSC_setattrlist 	0x040C0374	
#define BSC_getdirentriesattr	0x040C0378	
#define BSC_exchangedata	0x040C037C	
#define BSC_checkuseraccess	0x040C0380	
#define BSC_searchfs    	0x040C0384
#define BSC_delete      	0x040C0388
#define BSC_copyfile   		0x040C038C
#define BSC_fgetattrlist	0x040C0390
#define BSC_fsetattrlist	0x040C0394
#define BSC_getxattr		0x040C03A8
#define BSC_fgetxattr		0x040C03AC
#define BSC_setxattr		0x040C03B0
#define BSC_fsetxattr		0x040C03B4
#define BSC_removexattr		0x040C03B8
#define BSC_fremovexattr	0x040C03BC
#define BSC_listxattr		0x040C03C0
#define BSC_flistxattr		0x040C03C4
#define BSC_fsctl       	0x040C03C8
#define BSC_posix_spawn       	0x040C03D0
#define BSC_ffsctl       	0x040C03D4
#define BSC_open_extended	0x040C0454
#define BSC_umask_extended	0x040C0458
#define BSC_stat_extended	0x040C045C
#define BSC_lstat_extended	0x040C0460
#define BSC_fstat_extended	0x040C0464
#define BSC_chmod_extended	0x040C0468
#define BSC_fchmod_extended	0x040C046C
#define BSC_access_extended	0x040C0470
#define BSC_mkfifo_extended	0x040C048C
#define BSC_mkdir_extended	0x040C0490
#define BSC_aio_fsync		0x040C04E4
#define	BSC_aio_return		0x040C04E8
#define BSC_aio_suspend		0x040C04EC
#define BSC_aio_cancel		0x040C04F0
#define BSC_aio_error		0x040C04F4
#define BSC_aio_read		0x040C04F8
#define BSC_aio_write		0x040C04FC
#define BSC_lio_listio		0x040C0500
#define BSC_sendfile		0x040C0544
#define BSC_stat64		0x040C0548
#define BSC_fstat64		0x040C054C
#define BSC_lstat64		0x040C0550
#define BSC_stat64_extended	0x040C0554
#define BSC_lstat64_extended	0x040C0558
#define BSC_fstat64_extended	0x040C055C
#define BSC_getdirentries64	0x040C0560
#define BSC_statfs64		0x040C0564
#define BSC_fstatfs64		0x040C0568
#define BSC_getfsstat64		0x040C056C
#define BSC_pthread_chdir	0x040C0570
#define BSC_pthread_fchdir	0x040C0574
#define BSC_lchown		0x040C05B0

#define BSC_read_nocancel	0x040c0630
#define BSC_write_nocancel	0x040c0634
#define BSC_open_nocancel	0x040c0638
#define BSC_close_nocancel      0x040c063c
#define BSC_msync_nocancel	0x040c0654
#define BSC_fcntl_nocancel	0x040c0658
#define BSC_select_nocancel	0x040c065c
#define BSC_fsync_nocancel	0x040c0660
#define BSC_readv_nocancel	0x040c066c
#define BSC_writev_nocancel	0x040c0670
#define BSC_pread_nocancel	0x040c0678
#define BSC_pwrite_nocancel	0x040c067c
#define BSC_aio_suspend_nocancel	0x40c0694
#define BSC_guarded_open_np	0x040c06e4
#define BSC_guarded_close_np	0x040c06e8

#define BSC_fsgetpath		0x040c06ac

#define	BSC_getattrlistbulk 0x040c0734

#define BSC_openat		0x040c073c
#define BSC_openat_nocancel	0x040c0740
#define BSC_renameat		0x040c0744
#define BSC_chmodat		0x040c074c
#define BSC_chownat		0x040c0750
#define BSC_fstatat		0x040c0754
#define BSC_fstatat64		0x040c0758
#define BSC_linkat		0x040c075c
#define BSC_unlinkat		0x040c0760
#define BSC_readlinkat		0x040c0764
#define BSC_symlinkat		0x040c0768
#define BSC_mkdirat		0x040c076c
#define BSC_getattrlistat	0x040c0770

#define BSC_msync_extended	0x040e0104
#define BSC_pread_extended	0x040e0264
#define BSC_pwrite_extended	0x040e0268
#define BSC_mmap_extended	0x040e0314
#define BSC_mmap_extended2	0x040f0314

#define MAX_BSD_SYSCALL	526

#define MAX_PIDS 256
static int pids[MAX_PIDS];
static int num_of_pids = 0;
static int exclude_pids = 0;
static int exclude_default_pids = 1;
static struct kinfo_proc *kp_buffer = 0;
static int kp_nentries = 0;

#define EVENT_BASE 60000
const int num_events = EVENT_BASE * 8;

#define DBG_FUNC_ALL	(DBG_FUNC_START | DBG_FUNC_END)
#define DBG_FUNC_MASK	0xfffffffc

static int mib[6];
static size_t needed;
static char  *my_buffer;

static kbufinfo_t bufinfo = {0, 0, 0, 0, 0};

static void create_map_entry(uintptr_t thread, int pid, char *command) {
	threadmap_t tme;
	int hashid;

	if ((tme = threadmap_freelist)) {
		threadmap_freelist = tme->tm_next;
	} else {
		tme = (threadmap_t)calloc(1, sizeof(struct threadmap));
	}

	tme->tm_thread = thread;
	tme->tm_pid = pid;
	tme->tm_setsize = 0;
	tme->tm_setptr  = 0;

	(void)strncpy (tme->tm_command, command, MAXCOMLEN);
	tme->tm_command[MAXCOMLEN] = '\0';

	hashid = thread & HASH_MASK;

	tme->tm_next = threadmap_hash[hashid];
	threadmap_hash[hashid] = tme;
}

static threadmap_t find_map_entry(uintptr_t thread) {
	threadmap_t     tme;
	int     hashid = thread & HASH_MASK;
	for (tme = threadmap_hash[hashid]; tme; tme = tme->tm_next) {
		if (tme->tm_thread == thread)
			return tme;
	}
	return NULL;
}

static void delete_map_entry(uintptr_t thread) {
	threadmap_t tme = 0;
	threadmap_t tme_prev;
	int hashid;

	hashid = thread & HASH_MASK;

	if ((tme = threadmap_hash[hashid])) {
		if (tme->tm_thread == thread)
			threadmap_hash[hashid] = tme->tm_next;
		else {
			tme_prev = tme;

			for (tme = tme->tm_next; tme; tme = tme->tm_next) {
				if (tme->tm_thread == thread) {
					tme_prev->tm_next = tme->tm_next;
					break;
				}
				tme_prev = tme;
			}
		}
		if (tme) {
			if (tme->tm_setptr)
				free (tme->tm_setptr);

			tme->tm_next = threadmap_freelist;
			threadmap_freelist = tme;
		}
	}
}


static bool set_enable(bool val) {
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDENABLE;
	mib[3] = val;
	mib[4] = 0;
	mib[5] = 0;
	if (sysctl (mib, 4, NULL, &needed, NULL, 0) < 0) {
		eprintf ("trace facility failure, KERN_KDENABLE\n");
		return false;
	}
	return true;
}

static void set_remove() {
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDREMOVE;
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;
	(void)sysctl (mib, 3, NULL, &needed, NULL, 0);
}

static void quit(char *s) {
	set_enable (false);
	set_remove ();
	eprintf ("fs_usage: ");
	if (s) {
		eprintf ("%s", s);
	}
	running = false;
}

#if 0
static char *parse_access(int arg2) {
	static char mode[64] = {'_'};
	memset (mode, '_', sizeof(mode));
	mode[4] = '\0';
	arg2 &= 0xf;
	if (arg2 & R_OK) mode[0] = 'r';
	if (arg2 & W_OK) mode[1] = 'w';
	if (arg2 & X_OK) mode[2] = 'x';
	if (arg2 == F_OK) mode[3] = 'f';
	return mode;
}
#endif

static char *parse_openarg(int arg2) {
	static char mode[7];

	memset (mode, '_', 6);
	mode[6] = '\0';

	if (arg2 & O_RDWR) {
		mode[0] = 'R';
		mode[1] = 'W';
	} else if (arg2 & O_WRONLY) {
		mode[1] = 'W';
	} else {
		mode[0] = 'R';
	}
	if (arg2 & O_CREAT) mode[2] = 'c';
	if (arg2 & O_APPEND) mode[3] = 'a';
	if (arg2 & O_TRUNC) mode[4] = 't';
	if (arg2 & O_EXCL) mode[5] = 'e';
	return mode;
}

static void set_pidcheck(int pid, int on_off) {
	kd_regtype kr;

	kr.type = KDBG_TYPENONE;
	kr.value1 = pid;
	kr.value2 = on_off;
	needed = sizeof(kd_regtype);
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDPIDTR;
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;

	if (sysctl(mib, 3, &kr, &needed, NULL, 0) < 0) {
		if (on_off == 1)
			eprintf ("pid %d does not exist\n", pid);
	} else {
		one_good_pid++;
	}
}

/* 
 * on_off == 0 turns off pid exclusion
 * on_off == 1 turns on pid exclusion
 */
static void set_pidexclude(int pid, int on_off) {
	kd_regtype kr;

	one_good_pid++;

	kr.type = KDBG_TYPENONE;
	kr.value1 = pid;
	kr.value2 = on_off;
	needed = sizeof(kd_regtype);
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDPIDEX;
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;

	if (sysctl (mib, 3, &kr, &needed, NULL, 0) < 0) {
		if (on_off == 1)
			eprintf ("pid %d does not exist\n", pid);
	}
}

// XXX not necessary imho
bool kdebug_stop() {
	int i;
	if (!running) {
		return false;
	}
	set_enable (false);

	if (exclude_pids == 0) {
		for (i = 0; i < num_of_pids; i++)
			set_pidcheck (pids[i], 0);
	} else {
		for (i = 0; i < num_of_pids; i++)
			set_pidexclude (pids[i], 0);
	}
	set_remove ();
	running = false;
	return true;
}

static void exit_usage(const char *myname) {
	eprintf ("Usage: %s [-e] [pid | cmd [pid | cmd] ...]\n", myname);
	eprintf ("  -e    exclude the specified list of pids from the sample\n");
	eprintf ("\n%s will handle a maximum list of %d pids.\n\n", myname, MAX_PIDS);
	eprintf ("By default (no options) the following processes are excluded from the output:\n");
	eprintf ("fs_usage, Terminal, telnetd, sshd, rlogind, tcsh, csh, sh\n\n");
}

int filemgr_index(type) {
	if (type & 0x10000)
		return (((type >> 2) & 0x3fff) + 256);
	return (((type >> 2) & 0x3fff));
}

static bool set_init() {
	kd_regtype kr = {0};
	kr.type = KDBG_RANGETYPE;
	kr.value1 = 0;
	kr.value2 = -1;
	needed = sizeof (kd_regtype);

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDSETREG;		
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;
	if (sysctl (mib, 3, &kr, &needed, NULL, 0) < 0) {
		quit("trace facility failure, KERN_KDSETREG\n");
	}
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDSETUP;		
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;
	if (sysctl (mib, 3, NULL, &needed, NULL, 0) < 0) {
		quit("trace facility failure, KERN_KDSETUP\n");
	}
	return true;
}

static void set_filter(void) {
#define CSC(class, subclass) \
	( (uint16_t) ( ((class) & 0xff) << 8 ) | ((subclass) & 0xff) )
	uint8_t type_filter_bitmap[KDBG_TYPEFILTER_BITMAP_SIZE] = { 0 };

	setbit (type_filter_bitmap, CSC (DBG_TRACE,DBG_TRACE_DATA));
	setbit (type_filter_bitmap, CSC (DBG_TRACE,DBG_TRACE_STRING));

	setbit (type_filter_bitmap, CSC (DBG_MACH,DBG_MACH_EXCP_SC)); //0x010c
	setbit (type_filter_bitmap, CSC (DBG_MACH,DBG_MACH_VM)); //0x0130

	setbit (type_filter_bitmap, CSC (DBG_FSYSTEM,DBG_FSRW)); //0x0301
	setbit (type_filter_bitmap, CSC (DBG_FSYSTEM,DBG_DKRW)); //0x0302
	// setbit (type_filter_bitmap, CSC (DBG_FSYSTEM,DBG_IOCTL)); //0x0306
	setbit (type_filter_bitmap, CSC (DBG_FSYSTEM,DBG_BOOTCACHE)); //0x0307

	setbit (type_filter_bitmap, CSC (DBG_BSD,DBG_BSD_EXCP_SC)); //0x040c
	setbit (type_filter_bitmap, CSC (DBG_BSD,DBG_BSD_PROC)); //0x0401
	setbit (type_filter_bitmap, CSC (DBG_BSD,DBG_BSD_SC_EXTENDED_INFO)); //0x040e
	setbit (type_filter_bitmap, CSC (DBG_BSD,DBG_BSD_SC_EXTENDED_INFO2)); //0x040f

	setbit (type_filter_bitmap, CSC (DBG_CORESTORAGE,DBG_CS_IO)); //0x0a00
	setbit (type_filter_bitmap, CSC (DBG_CORESTORAGE, 1)); //0x0a01 for P_SCCS_SYNC_DIS

	int mib[] = { CTL_KERN, KERN_KDEBUG, KERN_KDSET_TYPEFILTER };
	size_t needed = KDBG_TYPEFILTER_BITMAP_SIZE;
	if (sysctl (mib, 3, type_filter_bitmap, &needed, NULL, 0)) {
		quit("trace facility failure, KERN_KDSET_TYPEFILTER\n");
	}
}

static bool set_numbufs(int nbufs) {
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDSETBUF;
	mib[3] = nbufs;
	mib[4] = 0;
	mib[5] = 0;
	if (sysctl (mib, 4, NULL, &needed, NULL, 0) < 0) {
		quit ("trace facility failure, KERN_KDSETBUF\n");
		return false;
	}
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDSETUP;
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;
	if (sysctl (mib, 3, NULL, &needed, NULL, 0) < 0) {
		quit ("trace facility failure, KERN_KDSETUP\n");
		return false;
	}
	return true;
}

static bool find_proc_names() {
	size_t bufSize = 0;
	struct kinfo_proc *kp;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_ALL;
	mib[3] = 0;

	if (sysctl (mib, 4, NULL, &bufSize, NULL, 0) < 0) {
		eprintf ("trace facility failure, KERN_PROC_ALL\n");
		return false;
	}
	if ((kp = (struct kinfo_proc *)calloc (1, bufSize)) == (struct kinfo_proc *)0) {
		eprintf ("can't allocate memory for proc buffer\n");
		return false;
	}
	if (sysctl(mib, 4, kp, &bufSize, NULL, 0) < 0) {
		eprintf ("trace facility failure, KERN_PROC_ALL\n");
		return false;
	}

	kp_nentries = bufSize / sizeof (struct kinfo_proc);
	kp_buffer = kp;
	return true;
}

static void get_bufinfo(kbufinfo_t *val) {
	needed = sizeof (*val);
	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDGETBUF;		
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;
	if (sysctl (mib, 3, val, &needed, 0, 0) < 0) {
		quit("trace facility failure, KERN_KDGETBUF\n");
	}
}

static char * vnode_set (uint64_t vn_id, char *pathname) {
	vnode_info_t vn;
	int hashid = (vn_id >> VN_HASH_SHIFT) & VN_HASH_MASK;
	for (vn = vn_info_hash[hashid]; vn; vn = vn->vn_next) {
		if (vn->vn_id == vn_id) {
			break;
		}
	}
	if (!vn) {
		vn = (vnode_info_t)calloc (1, sizeof (struct vnode_info));
		if (!vn) {
			return NULL;
		}
		vn->vn_next = vn_info_hash[hashid];
		vn_info_hash[hashid] = vn;
		vn->vn_id = vn_id;
	}
	strcpy ((char *)vn->vn_pathname, pathname);
	return (vn->vn_pathname);
}

static char * vnode_get (uint64_t vn_id) {
	vnode_info_t vn;
	int hashid = (vn_id >> VN_HASH_SHIFT) & VN_HASH_MASK;
	for (vn = vn_info_hash[hashid]; vn; vn = vn->vn_next) {
		if (vn->vn_id == vn_id) {
			return (char *)&vn->vn_pathname;
		}
	}
	return "";
}

static void handle_syscall (int type, uintptr_t thread, uint64_t arg1, uint64_t arg2, uint64_t vnodeid) {
	const char *pathname = vnodeid ? vnode_get (vnodeid): "";
	int pid = thread; // TODO resolve pid and procname here
	threadmap_t tme;
	const char *procname = "";
	int args = 0;
	const char *scname = NULL;
	if ((tme = find_map_entry (thread))) {
		pid = tme->tm_pid;
		procname = tme->tm_command;
	}

	switch (type) {
#if 0
	case BSC_lstat:
	case BSC_lstat64:
	case BSC_lstat_extended:
	case BSC_lstat64_extended:
		printf ("SYSCALL lstat\n");
		break;
	case BSC_statfs:
	case BSC_statfs64:
		printf ("SYSCALL statfs\n");
		break;
	case BSC_fstat:
	case BSC_fstat64:
	case BSC_fstat_extended:
	case BSC_fstat64_extended:
		printf ("SYSCALL fstat\n");
		break;
	case BSC_stat:
	case BSC_stat64:
	case BSC_stat_extended:
	case BSC_stat64_extended:
		printf ("SYSCALL stat\n");
		break;
	case BSC_undelete:
#endif
	case BSC_unlink:
	case BSC_delete:
		scname = "unlink";
		args = BSC_unlink;
		break;
	case BSC_copyfile:
		scname = "copyfile";
		args = BSC_rename;
		break;
	case BSC_truncate:
		scname = "truncate";
		args = BSC_unlink;
		break;
	case BSC_rmdir:
		scname = "rmdir";
		args = BSC_unlink;
		break;
	case BSC_mkdir:
	case BSC_mkdirat:
	case BSC_mkdir_extended:
		scname = "mkdir";
		args = BSC_unlink;
		break;
	case BSC_readlink:
		scname = "readlink";
		args = BSC_unlink;
		break;
	case BSC_link:
	case BSC_symlink:
		scname = "symlink";
		args = BSC_rename; // XXX
		break;
	case BSC_revoke:
		args = BSC_unlink;
		scname = "revoke";
		break;
	case BSC_mknod:
		scname = "mknod";
		args = BSC_unlink;
		break;
	case BSC_exit:
		scname = "exit";
		break;
	case BSC_chown:
	case BSC_lchown:
		scname = "chown";
		args = BSC_open; // XXX
		break;
	case BSC_fsgetpath:
		scname = "fsgetpath";
		args = BSC_unlink;
		break;
	case BSC_getxattr:
		scname = "getxattr";
		args = BSC_unlink;
		break;
	case BSC_access:
	case BSC_access_extended:
		scname = "access";
		args = BSC_unlink;
		break;
	case BSC_chdir:
	case BSC_pthread_chdir:
		scname = "chdir";
		args = BSC_unlink;
		break;
	case BSC_chroot:
		break;
	case BSC_chmod:
	case BSC_chmod_extended:
		scname = "chmod";
		break;
		args = BSC_open;
	case BSC_mount:
	case BSC_unmount:
		scname = "mount";
		args = BSC_unlink;
		break;
	case BSC_execve:
	case BSC_posix_spawn:
		scname = "execve";
		break;
	case BSC_old_creat:
		scname = "old_creat";
		args = BSC_unlink;
		break;
	case BSC_rename:
		scname = "rename";
		args = BSC_rename;
		break;
	case BSC_open:
	case BSC_open_nocancel:
		scname = "open";
		args = BSC_open;
		break;
	case BSC_open_extended:
	case BSC_open_dprotected_np:
		scname = "open_extended";
		args = BSC_open;
		break;
	}
	if (scname) {
		if (args > 0 && !*pathname) {
			return;
		}
		if (!*procname || !strcmp (procname, "Finder")) {
			return;
		}
#if WITH_MAIN
		printf ("PID %d (%s) SYSCALL %s", pid, procname, scname);
		switch (args) {
		case BSC_open:
			mode = arg2;
			printf (" %s MODE %s", pathname, parse_openarg (arg2));
			break;
		case BSC_unlink:
			printf (" %s", pathname);
			break;
		case BSC_rename:
			printf (" %s %s", pathname, pathname); // TODO: grab old name too
			break;
		}
		printf ("\n");
#else
		if (cb) {
			FileMonitorEvent ev = {0};
			ev.pid = pid;
			ev.type = FSE_CREATE_FILE;
			ev.type = FSE_RENAME;
			ev.proc = procname;
			ev.file = pathname;
			ev.event = scname;
			switch (type) {
			case BSC_rename:
				ev.type = FSE_RENAME;
				ev.newfile = pathname; // TODO
				break;
			case BSC_unlink:
			case BSC_delete:
				ev.type = FSE_DELETE;
				break;
			case BSC_copyfile:
				ev.type = FSE_CREATE_FILE;
				break;
			case BSC_truncate:
				ev.type = FSE_CREATE_FILE;
				break;
			case BSC_rmdir:
				ev.type = FSE_DELETE;
				break;
			case BSC_mkdir:
			case BSC_mkdirat:
			case BSC_mkdir_extended:
				ev.type = FSE_CREATE_DIR;
				break;
			case BSC_readlink:
				break;
			case BSC_link:
			case BSC_symlink:
				ev.type = FSE_CREATE_FILE;
				break;
			case BSC_revoke:
				ev.type = FSE_DELETE;
				break;
			case BSC_mknod:
				ev.type = FSE_CREATE_FILE;
				break;
			case BSC_chown:
			case BSC_lchown:
				ev.type = FSE_CHOWN;
				break;
			case BSC_fsgetpath:
			case BSC_getxattr:
				ev.type = FSE_STAT_CHANGED;
				break;
			case BSC_access:
			case BSC_access_extended:
				ev.type = FSE_OPEN;
				break;
			case BSC_chdir:
			case BSC_pthread_chdir:
				ev.type = FSE_CREATE_DIR; // XXX
				break;
			case BSC_chroot:
				ev.type = FSE_CREATE_DIR; // XXX
				break;
			case BSC_chmod:
			case BSC_chmod_extended:
				ev.type = FSE_STAT_CHANGED;
				break;
			case BSC_mount:
			case BSC_unmount:
				scname = "mount";
				args = BSC_unlink;
				break;
			case BSC_execve:
			case BSC_posix_spawn:
				ev.type = FSE_OPEN;
				break;
			case BSC_old_creat:
				ev.type = FSE_CREATE_FILE;
				break;
			case BSC_open:
			case BSC_open_nocancel:
			case BSC_open_extended:
			case BSC_open_dprotected_np:
				ev.type = FSE_OPEN;
				ev.mode = (int)arg2;
				break;
			}
			cb (fm, &ev);
		}
#endif
		if (type == BSC_exit) {
			delete_map_entry (thread);
		}
	}
}

static th_info_t add_event(uintptr_t thread, int type) {
	th_info_t ti;
	int i, hashid;

	if ((ti = th_info_freelist)) {
		th_info_freelist = ti->next;
	} else {
		ti = (th_info_t)calloc(1, sizeof(struct th_info));
	}

	hashid = thread & HASH_MASK;
	ti->next = th_info_hash[hashid];
	th_info_hash[hashid] = ti;
	ti->thread = thread;
	ti->type = type;

	ti->pathptr = (uintptr_t*)&ti->lookups[0].pathname;
	ti->pn_scall_index = 0;
	ti->pn_work_index = 0;

	for (i = 0; i < MAX_PATHNAMES; i++) {
		ti->lookups[i].pathname[0] = 0;
	}
	return (ti);
}

static void enter_event(uintptr_t thread, int type, kd_buf *kd, char *name, struct th_info *ti) {
#define P_CS_SYNC_DISK		0x0a010000
	int index;

	switch (type) {
	case P_CS_SYNC_DISK:
	case MACH_pageout:
	case MACH_vmfault:
	case MSC_map_fd:
	case SPEC_ioctl:
	case Throttled:
	case HFS_update:
		add_event (thread, type);
		return;
	}
	if ((type & CSC_MASK) == BSC_BASE) {
		if ((index = BSC_INDEX(type)) >= MAX_BSD_SYSCALL) {
			return;
		}
		handle_syscall (type, thread, kd->arg1, kd->arg2, ti? ti->vnodeid: 0);
		return;
	}
}

static void delete_event(th_info_t ti_to_delete) {
	th_info_t ti;
	th_info_t ti_prev;
	int hashid;

	hashid = ti_to_delete->thread & HASH_MASK;

	if ((ti = th_info_hash[hashid])) {
		if (ti == ti_to_delete) {
			th_info_hash[hashid] = ti->next;
		} else {
			ti_prev = ti;

			for (ti = ti->next; ti; ti = ti->next) {
				if (ti == ti_to_delete) {
					ti_prev->next = ti->next;
					break;
				}
				ti_prev = ti;
			}
		}
		if (ti) {
			ti->next = th_info_freelist;
			th_info_freelist = ti;
		}
	}
}

static th_info_t find_event(uintptr_t thread, int type) {
	th_info_t ti;
	int hashid = thread & HASH_MASK;
	for (ti = th_info_hash[hashid]; ti; ti = ti->next) {
		if (ti->thread == thread) {
			if (type == ti->type || type == 0) {
				return ti;
			}
		}
	}
	return NULL;
}

static void exit_event(char *sc_name, uintptr_t thread, int type) {
	th_info_t ti;
	if ((ti = find_event(thread, type)) == (struct th_info *)0) {
		return;
	}
	ti->nameptr = 0;
	delete_event (ti);
}

static void delete_all_events() {
	th_info_t ti = 0;
	th_info_t ti_next = 0;
	int i;
	for (i = 0; i < HASH_SIZE; i++) {
		for (ti = th_info_hash[i]; ti; ti = ti_next) {
			ti_next = ti->next;
			ti->next = th_info_freelist;
			th_info_freelist = ti;
		}
		th_info_hash[i] = 0;
	}
}

static void delete_all_map_entries() {
	threadmap_t tme = 0;
	threadmap_t tme_next = 0;
	int i;

	for (i = 0; i < HASH_SIZE; i++) {
		for (tme = threadmap_hash[i]; tme; tme = tme_next) {
			if (tme->tm_setptr)
				free (tme->tm_setptr);
			tme_next = tme->tm_next;
			tme->tm_next = threadmap_freelist;
			threadmap_freelist = tme;
		}
		threadmap_hash[i] = 0;
	}
}

static bool read_command_map() {
	int i, n_threads = 0;
	kd_threadmap *mapptr = 0;
	if (!need_new_map) {
		return false;
	}
	delete_all_map_entries ();

	n_threads = bufinfo.nkdthreads;
	if (n_threads < 1) {
		return false;
	}
	if ((mapptr = (kd_threadmap *) calloc (n_threads, sizeof (kd_threadmap)))) {
		size_t size = n_threads * sizeof (kd_threadmap);
		mib[0] = CTL_KERN; /* read the thread map */
		mib[1] = KERN_KDEBUG;
		mib[2] = KERN_KDTHRMAP;
		mib[3] = 0;
		mib[4] = 0;
		mib[5] = 0;
		if (sysctl (mib, 3, mapptr, &size, NULL, 0) < 0) {
			free (mapptr);
			return false;
		}
		for (i = 0; i < n_threads; i++) {
			create_map_entry (mapptr[i].thread, mapptr[i].valid, &mapptr[i].command[0]);
		}
		free (mapptr);
	}
	need_new_map = false;
	return true;
}

bool kdebug_loop_once() {
	th_info_t ti = {0};
	size_t needed;
	kd_buf *kd;
	int i;

	get_bufinfo (&bufinfo);
	read_command_map ();
	needed = bufinfo.nkdbufs * sizeof (kd_buf);

	mib[0] = CTL_KERN;
	mib[1] = KERN_KDEBUG;
	mib[2] = KERN_KDREADTR;		
	mib[3] = 0;
	mib[4] = 0;
	mib[5] = 0;		/* no flags */
	if (!my_buffer) {
		if ((my_buffer = calloc (num_events, sizeof (kd_buf))) == (char *)0) {

			return 1;
		}
	}
	memset (my_buffer, 0, needed);
	if (sysctl (mib, 3, my_buffer, &needed, NULL, 0) < 0) {
		quit ("trace facility failure, KERN_KDREADTR\n");
		return false;
	}

	if (bufinfo.flags & KDBG_WRAPPED) {
		eprintf ("fs_usage: buffer overrun, events generated too quickly: %d\n", (int)needed);
		delete_all_events ();
		need_new_map = true;
		set_enable (0);
		set_enable (1);
	}
	kd = (kd_buf *)my_buffer;
	for (i = 0; i < needed; i++) {
		uint32_t debugid;
		uintptr_t thread;
		int type;
		uintptr_t *sargptr;

		thread = kd[i].arg5;
		debugid = kd[i].debugid;
		type = kd[i].debugid & DBG_FUNC_MASK;

		switch (type) {
		case TRACE_DATA_NEWTHREAD:
			if (kd[i].arg1) {
				if ((ti = add_event (thread, TRACE_DATA_NEWTHREAD)) == NULL)
					continue;
				ti->child_thread = kd[i].arg1;
				ti->pid = kd[i].arg2;
				dprintf ("PID %d (thread = %d)\n", (int)ti->pid, (int)thread);
			}
			continue;
		case TRACE_STRING_NEWTHREAD:
			if ((ti = find_event(thread, TRACE_DATA_NEWTHREAD)) == (struct th_info *)0)
				continue;
//printf ("THREAD %d th(%d) %s\n", (int)thread, (int)ti->pid, (char *)&kd[i].arg1);
			create_map_entry (ti->child_thread, ti->pid, (char *)&kd[i].arg1);
			delete_event (ti);
			continue;
		case TRACE_DATA_EXEC:
			if ((ti = add_event (thread, TRACE_DATA_EXEC)) == NULL) {
				continue;
			}
			ti->pid = kd[i].arg1;
			dprintf ("PID %d (thread = %d)\n", ti->pid, (int)thread);
			continue;
		case TRACE_STRING_EXEC:
			if ((ti = find_event (thread, BSC_execve))) {
				if (ti->lookups[0].pathname[0])
					exit_event("execve", thread, BSC_execve);

			} else if ((ti = find_event(thread, BSC_posix_spawn))) {
				if (ti->lookups[0].pathname[0])
					exit_event("posix_spawn", thread, BSC_posix_spawn);
			}
			if ((ti = find_event (thread, TRACE_DATA_EXEC)) == (struct th_info *)0) {
				continue;
			}
//printf ("THREAD %d th(%d) %s\n", (int)thread, (int)ti->pid, (char *)&kd[i].arg1);
			create_map_entry (thread, ti->pid, (char *)&kd[i].arg1);
			delete_event (ti);
			continue;
		case BSC_thread_terminate:
			delete_map_entry (thread);
			continue;
		case proc_exit:
			kd[i].arg1 = kd[i].arg2 >> 8;
			delete_map_entry (thread);
			type = BSC_exit;
			break;
		case HFS_update:
			if ((ti = find_event (thread, 0))) {
				if (ti->nameptr) {
					dprintf ("PATH UPDATE %d BLKEND %s\n", (int)kd[i].arg2, ti->nameptr);
				}
				// add_meta_name(kd[i].arg2, ti->nameptr);
			}
			continue;
			break;
		case HFS_modify_block_end:
			if ((ti = find_event(thread, 0))) {
				if (ti->nameptr) {
					dprintf ("PATH MODIFY %d BLKEND %s\n", (int)kd[i].arg2, ti->nameptr);
					//add_meta_name(kd[i].arg2, ti->nameptr);
				}
			}
			continue;
		case VFS_LOOKUP:
			if ((ti = find_event (thread, 0)) == (struct th_info *)0) {
				continue;
			}
			if (debugid & DBG_FUNC_START) {
				if (ti->pn_scall_index >= MAX_SCALL_PATHNAMES) {
					continue;
				}
				ti->pn_work_index = ti->pn_scall_index;
				sargptr = &ti->lookups[ti->pn_work_index].pathname[0];
				ti->vnodeid = kd[i].arg1;
				*sargptr++ = kd[i].arg2;
				*sargptr++ = kd[i].arg3;
				*sargptr++ = kd[i].arg4;
				*sargptr = 0;
				ti->pathptr = sargptr;
			} else {
				sargptr = ti->pathptr;
				/*
				 * We don't want to overrun our pathname buffer if the
				 * kernel sends us more VFS_LOOKUP entries than we can
				 * handle and we only handle 2 pathname lookups for
				 * a given system call
				 */
				if (sargptr == 0) {
					continue;
				}
				if ((uintptr_t)sargptr < (uintptr_t)&ti->lookups[ti->pn_work_index].pathname[NUMPARMS]) {
					*sargptr++ = kd[i].arg1;
					*sargptr++ = kd[i].arg2;
					*sargptr++ = kd[i].arg3;
					*sargptr++ = kd[i].arg4;
					/*
					 * NULL terminate the 'string'
					 */
					*sargptr = 0;
				}
			}
			if (debugid & DBG_FUNC_END) {
//printf ("ADD VNODE 0x%x %s\n", (uint32_t)ti->vnodeid, (char *)&ti->lookups[ti->pn_work_index].pathname[0]);
				ti->nameptr = vnode_set (ti->vnodeid, (char *)&ti->lookups[ti->pn_work_index].pathname[0]);
				if (ti->pn_work_index == ti->pn_scall_index) {
					ti->pn_scall_index++;
					if (ti->pn_scall_index < MAX_SCALL_PATHNAMES) {
						ti->pathptr = &ti->lookups[ti->pn_scall_index].pathname[0];
					} else {
						ti->pathptr = 0;
					}
				}
			} else {
				ti->pathptr = sargptr;
			}
			continue;
		}
		if (debugid & DBG_FUNC_START) {
			enter_event (thread, type, &kd[i], NULL, ti);
			continue;
		}
		if ((type & CSC_MASK) == BSC_BASE) {
			if (BSC_INDEX (type) >= MAX_BSD_SYSCALL) {
				continue;
			}
			handle_syscall (type, thread, kd[i].arg1, kd[i].arg2, ti? ti->vnodeid: 0);
		}
	}
	return true;
}

#if 0
static bool add_meta_name(uint64_t blockno, char *pathname) {
	meta_info_t mi;
	int hashid = blockno & VN_HASH_MASK;

	for (mi = m_info_hash[hashid]; mi; mi = mi->m_next) {
		if (mi->m_blkno == blockno) {
			break;
		}
	}
	if (mi == NULL) {
		mi = (meta_info_t)calloc (1, sizeof (struct meta_info));
		if (!mi) {
			return false;
		}
		mi->m_next = m_info_hash[hashid];
		m_info_hash[hashid] = mi;
		mi->m_blkno = blockno;
	}
	mi->m_nameptr = pathname;
	return true;
}

static char * find_meta_name(uint64_t blockno) {
	meta_info_t mi;
	int hashid = blockno & VN_HASH_MASK;

	for (mi = m_info_hash[hashid]; mi; mi = mi->m_next) {
		if (mi->m_blkno == blockno) {
			return (mi->m_nameptr);
		}
	}
	return "";
}
#endif

void argtopid(char *str) {
	char *cp;
	int ret;
	int i;

	ret = (int)strtol(str, &cp, 10);

	if (cp == str || *cp) {
		/*
		 * Assume this is a command string and find matching pids
		 */
		if (!kp_buffer) {
			find_proc_names ();
		}
		for (i = 0; i < kp_nentries && num_of_pids < (MAX_PIDS - 1); i++) {
			if (kp_buffer[i].kp_proc.p_stat == 0) {
				continue;
			} else {
				if (!strncmp (str, kp_buffer[i].kp_proc.p_comm,
							sizeof(kp_buffer[i].kp_proc.p_comm) -1))
					pids[num_of_pids++] = kp_buffer[i].kp_proc.p_pid;
			}
		}
	} else if (num_of_pids < (MAX_PIDS - 1)) {
		pids[num_of_pids++] = ret;
	}
}

bool kdebug_begin() {
	if (exclude_default_pids) {
		argtopid ("iTerm2");
		argtopid ("Finder");
		argtopid ("com.docker.db");
		argtopid ("Terminal");
		argtopid ("telnetd");
		argtopid ("telnet");
		argtopid ("sshd");
		argtopid ("rlogind");
		argtopid ("tcsh");
		argtopid ("csh");
		argtopid ("sh");
		exclude_pids = 1;
	}
	set_remove ();
	set_numbufs (num_events);
	set_init ();
	set_filter ();
	set_enable (true);
	return true;
}

#if WITH_MAIN
static void leave() {
	(void)kdebug_stop();
}

/* main */
int main(int argc, char **argv) {
	const char *myname = "kdebug";
	int i, ch;

	while ((ch = getopt (argc, argv, "e")) != -1) {
		switch (ch) {
		case 'e':
			exclude_pids = 1;
			exclude_default_pids = 0;
			break;
		default:
			exit_usage (myname);		 
			return 1;
		}
	}
	argc -= optind;
	argv += optind;
	/*
	 * when excluding, fs_usage should be the first in line for pids[]
	 * 
	 * the !exclude_pids && argc == 0 catches the exclude_default_pids
	 * case below where exclude_pids is later set and the fs_usage PID
	 * needs to make it into pids[] 
	 */
	if (exclude_pids || (!exclude_pids && argc == 0)) {
		if (num_of_pids < (MAX_PIDS - 1)) {
			pids[num_of_pids++] = getpid();
		}
	}

	/*
	 * If we process any list of pids/cmds, then turn off the defaults
	 */
	if (argc > 0) {
		exclude_default_pids = 0;
	}
	while (argc > 0 && num_of_pids < (MAX_PIDS - 1)) {
		select_pid_mode++;
		argtopid (argv[0]);
		argc--;
		argv++;
	}
	/*
	 * Exclude a set of default pids
	 */
#if 1
	if (exclude_default_pids) {
		argtopid ("iTerm2");
		argtopid ("Finder");
		argtopid ("com.docker.db");
		argtopid ("Terminal");
		argtopid ("telnetd");
		argtopid ("telnet");
		argtopid ("sshd");
		argtopid ("rlogind");
		argtopid ("tcsh");
		argtopid ("csh");
		argtopid ("sh");
		exclude_pids = 1;
	}
#endif
	/* set up signal handlers */
	signal (SIGINT, leave);
	signal (SIGQUIT, leave);
	signal (SIGPIPE, leave);
	signal (SIGTERM, leave);

	if ((my_buffer = calloc (num_events, sizeof (kd_buf))) == (char *)0) {
		quit ("can't allocate memory for tracing info\n");
		return 1;
	}

	set_remove ();
	set_numbufs (num_events);
	set_init ();

	if (exclude_pids == 0) {
		for (i = 0; i < num_of_pids; i++)
			set_pidcheck(pids[i], 1);
	} else {
		for (i = 0; i < num_of_pids; i++)
			set_pidexclude(pids[i], 1);
	}
	if (select_pid_mode && !one_good_pid) {
		/* 
		 *  An attempt to restrict output to a given
		 *  pid or command has failed. Exit gracefully
		 */
		set_remove ();
		exit_usage (myname);
		return 1;
	}
	set_filter ();
	set_enable (true);
	while (running) {
		kdebug_loop_once ();
		fflush (stdout);
	}
	return 0;
}
#endif
