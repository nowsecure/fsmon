#ifndef _FSMON_H_
#define _FSMON_H_

#define FSMON_VERSION "1.0"

#include <stdint.h>
#include "fsev.h"
#include "util.h"

#define eprintf(x,y...) fprintf(stderr,x,##y)

#define FM_DEV "/dev/fsevents"
#define FM_BUFSIZE 4096

typedef struct {
	int pid;
	int ppid;
	const char *proc;
	const char *file;
	const char *newfile; // renamed/moved
	int uid;
	int gid;
	int type;
	int mode;
	uint32_t inode;
	uint64_t tstamp;
	int dev_major;
	int dev_minor;
} FileMonitorEvent;

typedef struct {
	const char *root;
	const char *proc;
	const char *link;
	int pid;
	int child;
	int alarm;
	int fd;
	bool json;
	bool stop;
	bool fileonly;
	uint64_t count;
	void (*control_c)();
} FileMonitor;

typedef bool (*FileMonitorCallback)(FileMonitor *fm, FileMonitorEvent *ev);

bool fm_begin (FileMonitor *fm);
bool fm_loop (FileMonitor *fm, FileMonitorCallback cb);
bool fm_end (FileMonitor *fm);

#endif
