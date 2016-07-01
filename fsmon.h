#ifndef INCLUDE_FM_FSMON_H
#define INCLUDE_FM_FSMON_H

#define FSMON_VERSION "1.3"

#include <stdint.h>
#include <signal.h>
#include "fsev.h"
#include "util.h"

#define eprintf(x,y...) fprintf(stderr,x,##y)

struct filemonitor_backend_t;
struct filemonitor_event_t;
struct filemonitor_t;

struct filemonitor_event_t {
	int pid;
	int ppid;
	const char *proc;
	const char *file;
	const char *newfile; // renamed/moved
	const char *event; // named event
	int uid;
	int gid;
	int type;
	int mode;
	uint32_t inode;
	uint64_t tstamp;
	int dev_major;
	int dev_minor;
};

typedef bool (*FileMonitorCallback)(struct filemonitor_t *fm, struct filemonitor_event_t *ev);

struct filemonitor_backend_t {
	const char *name;
	bool (*begin)(struct filemonitor_t *fm);
	bool (*loop)(struct filemonitor_t *fm, FileMonitorCallback cb);
	bool (*end)(struct filemonitor_t *fm);
};

struct filemonitor_t {
	const char *root;
	const char *proc;
	const char *link;
	int pid;
	int child;
	int alarm;
	int fd;
	bool json;
	volatile sig_atomic_t running;
	bool fileonly;
	uint64_t count;
	void (*control_c)();
	struct filemonitor_backend_t backend;
};

typedef struct filemonitor_backend_t FileMonitorBackend;
typedef struct filemonitor_event_t FileMonitorEvent;
typedef struct filemonitor_t FileMonitor;

#if __APPLE__
extern FileMonitorBackend fmb_devfsev;
extern FileMonitorBackend fmb_fsevapi;
extern FileMonitorBackend fmb_kqueue;
extern FileMonitorBackend fmb_kdebug;
#else
extern FileMonitorBackend fmb_inotify;
#endif

#endif
