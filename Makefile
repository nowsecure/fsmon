ARCHS=armv7 arm64

CFLAGS+=-I.
CFLAGS+=-Wall

include config.mk
CFLAGS+=-DFSMON_VERSION=\"$(VERSION)\"

SOURCES=main.c util.c
SOURCES+=backend/*.c

TARGET_TRIPLE := $(shell $(CC) -dumpmachine 2>/dev/null)

ifneq ($(findstring -darwin,$(TARGET_TRIPLE)),)
	TARGET_OS_TYPE=Darwin
else ifneq ($(findstring -linux,$(TARGET_TRIPLE)),)
	TARGET_OS_TYPE=Linux
else ifneq ($(findstring -android,$(TARGET_TRIPLE)),)
	TARGET_OS_TYPE=Linux
else
	TARGET_OS_TYPE=$(shell uname)
endif

ifeq ($(TARGET_OS_TYPE),Linux)

# LINUX: GNU / ANDROID
#     __
#  -=(o '.
#     \.-.\
#     /|  \\
#     '|  ||
#      _\_):,_

FANOTIFY_CFLAGS+=-DHAVE_FANOTIFY=1
FANOTIFY_CFLAGS+=-DHAVE_SYS_FANOTIFY=1

all: fsmon

fsmon:
	$(CC) -o fsmon $(CFLAGS) $(FANOTIFY_CFLAGS) $(LDFLAGS) $(SOURCES)

DESTDIR?=
PREFIX?=/usr

clean:
	rm -f fsmon
	rm -rf fsmon-macos* fsmon-ios* fsmon-wch*
	rm -rf fsmon-and*
else
# APPLE: OSX / IOS / IWATCH
#     _
#    _\)/_
#   /     \
#   \     /
#    \_._/

DESTDIR?=
PREFIX?=/usr/local

# iOS
IOS_ARCHS=$(addprefix -arch ,$(ARCHS))
IOS_CFLAGS+=$(IOS_ARCHS)
IOS_CFLAGS+=-isysroot ${IOS_SYSROOT}
IOS_CFLAGS+=-flto
IOS_CFLAGS+=-target arm64-apple-ios10.0
IOS_CFLAGS+=-miphoneos-version-min=10.0
IOS_CFLAGS+=-O3 -Wall
ifeq ($(shell uname -m | grep -E "iPhone|iPad|iPod" > /dev/null ; echo $${?}),0)
IOS_ON_DEVICE_COMPILE=1
IOS_SYSROOT=/
IOS_CC=/usr/bin/clang
IOS_STRIP=/usr/bin/strip
LDID=/usr/bin/ldid
else
IOS_ON_DEVICE_COMPILE=0
IOS_SYSROOT=$(shell xcrun --sdk iphoneos --show-sdk-path)
IOS_CC=$(shell xcrun --sdk iphoneos --find clang) $(IOS_CFLAGS)
IOS_STRIP=xcrun --sdk iphoneos strip
LDID=bin/ldid_macosx_$(shell uname -m)
endif

# iWatch
WCH_CFLAGS=-arch armv7k
WCH_SYSROOT=$(shell xcrun --sdk watchos --show-sdk-path)
WCH_CFLAGS+=-isysroot ${WCH_SYSROOT}
WCH_CC=$(shell xcrun --sdk iphoneos --find clang) $(WCH_CFLAGS)

CC?=gcc
CFLAGS+=-g -ggdb

OBJS=fsmon.o main.o

all: macos

oldios:
	$(IOS_CC) $(CFLAGS) -DTARGET_IOS=1 -o fsmon-ios $(SOURCES) -framework CoreFoundation -framework MobileCoreServices
	$(IOS_STRIP) fsmon-ios
	if [ $(IOS_ON_DEVICE_COMPILE) != 1 ]; then \
		xcrun --sdk iphoneos codesign -f --entitlements ./entitlements.plist -s- fsmon-ios; fi

IOS_FRAMEWORKS=-framework CoreFoundation -weak_framework MobileCoreServices -weak_framework CoreServices
ios:
	$(IOS_CC) $(CFLAGS) -DTARGET_IOS=1 -o fsmon-ios $(SOURCES) $(IOS_FRAMEWORKS)
	ls -l fsmon-ios
	-$(IOS_STRIP) fsmon-ios
	if [ $(IOS_ON_DEVICE_COMPILE) != 1 ]; then \
	    xcrun --sdk iphoneos codesign -f --entitlements ./entitlements.plist -s- fsmon-ios; \
	fi
	$(LDID) -Sentitlements.plist fsmon-ios

ios2:
	$(MAKE) ios
	$(MAKE) ios-patch

ios-patch:
	rabin2 -x fsmon-ios
	export a=fsmon-ios.fat/fsmon-ios.arm_64* ; \
		export OFF=`rabin2 -H $$a | grep -C 2 /CoreSer | head -n1 | cut -d ' ' -f 1`; \
		echo OFF=$$OFF ; \
		r2 -qnwc "wx 18000080 @ $$OFF-4" $$a
	rm -f fsmon-ios
	lipo -create -arch arm64 fsmon-ios.fat/fsmon-ios.arm_64* -arch armv7 fsmon-ios.fat/fsmon-ios.arm_32* -output fsmon-ios
	-xcrun --sdk iphoneos codesign -f --entitlements ./entitlements.plist -s- fsmon-ios
	rm -rf fsmon-ios.fat

cydia: ios
	rm -rf dist/cydia/out
	$(MAKE) -C dist/cydia

macos:
	$(CC) $(CFLAGS) -mmacosx-version-min=10.12 -DTARGET_OSX=1 -o fsmon-macos $(SOURCES) -framework CoreServices
	strip fsmon-macos
	cp -f fsmon-macos fsmon

macos-pkg:
	./pkg.sh

wch:
	$(WCH_CC) $(CFLAGS) -DTARGET_WATCHOS=1 -o fsmon-wch $(SOURCES)

fat: ios macos wch
	lipo fsmon-ios -thin armv7 -output fsmon-ios-armv7
	lipo fsmon-ios -thin arm64 -output fsmon-ios-arm64
	lipo -create -output fsmon \
		-arch arm64 fsmon-ios-arm64 \
		-arch armv7 fsmon-ios-armv7 \
		-arch armv7k fsmon-wch \
		-arch x86_64 fsmon-macos
	strip fsmon
	codesign -s- fsmon

clean:
	rm -f fsmon-macos fsmon-ios
	rm -rf fsmon*.dSYM
	rm -f fsmon-and*

.PHONY: cydia ios macos macos-pkg fat wch

endif

BINDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/share/man/man1

install:
	mkdir -p $(BINDIR)
	install -m 0755 fsmon $(BINDIR)/fsmon
	mkdir -p $(MANDIR)
	install -m 0644 fsmon.1 $(MANDIR)/fsmon.1

uninstall:
	rm -f $(BINDIR)/fsmon
	rm -f $(MANDIR)/fsmon.1

# ANDROID
#
# \.-----./
# / o   o \
# `-------'

KITKAT_CFLAGS=-DHAVE_FANOTIFY=0 -DHAVE_SYS_FANOTIFY=0
LOLLIPOP_CFLAGS=-DHAVE_FANOTIFY=1 -DHAVE_SYS_FANOTIFY=0

NDK_ARCH?=
ANDROID_ARCHS=arm arm64 x86 x86_64
ANDROID_API?=

ifneq ($(NDK_ARCH),)
ANDROID_ARCHS=$(NDK_ARCH)
endif
ifeq ($(ANDROID_API),)
AAPIMODE=aagt21compile
else
AAPIMODE=$(shell test ${ANDROID_API} -gt 21 && echo aagt21compile || echo aalt21compile)
endif

andarm64:
	sh android-shell.sh arm64 make android

and android:
	for a in $(ANDROID_ARCHS) ; do \
		if [ -z "${NDK}" ] ; then \
			./android-shell.sh $$a \
			$(MAKE) $(AAPIMODE) ANDROID_API=$(ANDROID_API) NDK_ARCH=$$a ; \
		else \
			$(MAKE) $(AAPIMODE) ANDROID_API=$(ANDROID_API) NDK_ARCH=$$a ; \
		fi; \
	done

aagt21compile:
	ndk-gcc $(ANDROID_API) $(LOLLIPOP_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-and$(ANDROID_API)-$(NDK_ARCH) $(SOURCES)

aalt21compile:
	ndk-gcc $(ANDROID_API) $(KITKAT_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-and$(ANDROID_API)-$(NDK_ARCH) $(SOURCES)

.PHONY: all fsmon clean
.PHONY: install uninstall
.PHONY: and android
