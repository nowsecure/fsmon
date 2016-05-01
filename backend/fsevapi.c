/* fsmon -- MIT - Copyright NowSecure 2016 - pancake@nowsecure.com  */

#if __APPLE__
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include "fsmon.h"
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <sys/time.h>
#include <unistd.h>

#define FSEVAPI_DEBUG 1

#if TARGET_WATCHOS

#warning No FSEventMonitor API for WatchOS yet

#else

#include <CoreFoundation/CoreFoundation.h>

#if TARGET_IOS

#include <MobileCoreServices/MobileCoreServices.h>

const int kFSEventStreamCreateFlagFileEvents = 0x10;
const int kFSEventStreamEventIdSinceNow = -1;

typedef struct {
        CFIndex version;
        void *info;
        CFAllocatorRetainCallBack retain;
        CFAllocatorReleaseCallBack release;
        CFAllocatorCopyDescriptionCallBack copyDescription;
} FSEventStreamContext;

typedef void * ConstFSEventStreamRef;
typedef void * FSEventStreamRef;
typedef int FSEventStreamEventFlags;
typedef int FSEventStreamEventId;
typedef int FSEventStreamCreateFlags;

typedef void ( *FSEventStreamCallback )( ConstFSEventStreamRef streamRef, void *clientCallBackInfo, size_t numEvents, void *eventPaths, const FSEventStreamEventFlags eventFlags[], const FSEventStreamEventId eventIds[]);
extern FSEventStreamRef FSEventStreamCreate( CFAllocatorRef allocator, FSEventStreamCallback callback, FSEventStreamContext *context, CFArrayRef pathsToWatch, FSEventStreamEventId sinceWhen, CFTimeInterval latency, FSEventStreamCreateFlags flags);
extern Boolean FSEventStreamStart( FSEventStreamRef streamRef);
extern void FSEventStreamScheduleWithRunLoop( FSEventStreamRef streamRef, CFRunLoopRef runLoop, CFStringRef runLoopMode);

#else

#include <CoreServices/CoreServices.h>

#endif

/* TODO: move into event's ctx */
static FileMonitorCallback global_cb;

static void event_cb(ConstFSEventStreamRef streamRef, void *ctx, size_t count, void *paths,
                const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) {
	FileMonitor *fm = (FileMonitor*)ctx;
	FileMonitorEvent ev = {0};
	struct stat st;
        int i;

	if (!fm->running) {
		/* TODO: shouldnt wait until the next event */
		CFRunLoopStop (CFRunLoopGetCurrent ());
	}
        for (i = 0; i < count; i++) {
                char *path = ((char **)paths)[i];
#if FSEVAPI_DEBUG
                /* flags are unsigned long, IDs are uint64_t */
                printf ("%d Change 0x%" PRIx64 " in %s, flags %lu",
                        i, (uint64_t) ids[i], path, (long)flags[i]);
#endif
		if (stat (path, &st) != -1) {
			if ((S_IFREG & st.st_mode)==S_IFREG) {
				ev.type = FSE_CREATE_FILE;
			} else {
				ev.type = FSE_DELETE;
			}
		} else {
			/* XXX: the path is wrong */
			ev.type = FSE_DELETE;
		}
		ev.file = path;
		global_cb (fm, &ev);
        }
}

static bool fm_begin (FileMonitor *fm) {
        FSEventStreamCreateFlags flags = kFSEventStreamCreateFlagFileEvents;
        FSEventStreamContext ctx = {
                0,
                fm,
                NULL,
                NULL,
                NULL
        };

	if (!fm->root) {
		fm->root = "/";
	}
        CFMutableArrayRef paths = CFArrayCreateMutable (NULL, 1, NULL);
	CFStringRef cfs_path = CFStringCreateWithCString (NULL, fm->root,
		kCFStringEncodingUTF8);
	CFArrayAppendValue (paths, cfs_path);

        FSEventStreamRef stream = FSEventStreamCreate (NULL, &event_cb,
		&ctx, paths, kFSEventStreamEventIdSinceNow, 0, flags);
        FSEventStreamScheduleWithRunLoop (stream, CFRunLoopGetCurrent(),
		kCFRunLoopDefaultMode);
        FSEventStreamStart (stream);
	return true;
}

static bool fm_loop (FileMonitor *fm, FileMonitorCallback cb) {
	global_cb = cb;
	CFRunLoopRun ();
	return false;
}

static bool fm_end(FileMonitor *fm) {
	if (fm && fm->fd != -1) {
		close (fm->fd);
		fm->fd = -1;
		return true;
	}
	return false;
}

FileMonitorBackend fmb_fsevapi = {
	.name = "fsevapi",
	.begin = fm_begin,
	.loop = fm_loop,
	.end = fm_end,
};

#endif
#endif
