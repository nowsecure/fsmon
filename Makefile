ARCHS=armv7 arm64

ifeq ($(shell uname),Linux)
# LINUX: GNU / ANDROID
#     __
#  -=(o '.
#     \.-.\
#     /|  \\
#     '|  ||
#      _\_):,_

CFLAGS+=-Wall

all: fsmon

fsmon:
	$(CC) -o fsmon $(CFLAGS) $(LDFLAGS) os-linux.c main.c util.c

DESTDIR?=
PREFIX?=/usr

clean:
	rm -f fsmon
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
IOS_SYSROOT=$(shell xcrun --sdk iphoneos --show-sdk-path)
IOS_CFLAGS+=-isysroot ${IOS_SYSROOT}
IOS_CFLAGS+=-fembed-bitcode
IOS_CFLAGS+=-flto
IOS_CFLAGS+=-O3 -Wall
IOS_CC=$(shell xcrun --sdk iphoneos --find clang) $(IOS_CFLAGS)

# iWatch
WCH_CFLAGS=-arch armv7k
WCH_SYSROOT=$(shell xcrun --sdk watchos --show-sdk-path)
WCH_CFLAGS+=-isysroot ${WCH_SYSROOT}
IOS_CFLAGS+=-fembed-bitcode
WCH_CC=$(shell xcrun --sdk iphoneos --find clang) $(WCH_CFLAGS)

CC?=gcc
CFLAGS+=-g -ggdb

OBJS=fsmon.o main.o

all: ios osx wch
	$(MAKE) fat
	#scp fsmon-ios root@192.168.1.50:.

ios:
	$(IOS_CC) $(CFLAGS) -o fsmon-ios os-darwin.c main.c util.c
	strip fsmon-ios
	xcrun --sdk iphoneos codesign -s- fsmon-ios

cydia: ios
	$(MAKE) -C cydia

osx:
	$(CC) $(CFLAGS) -o fsmon-osx os-darwin.c main.c util.c
	strip fsmon-osx

osx-pkg:
	./pkg.sh

wch:
	$(WCH_CC) $(CFLAGS) -o fsmon-wch os-darwin.c main.c util.c

fat:
	lipo fsmon-ios -thin armv7 -output fsmon-ios-armv7
	lipo fsmon-ios -thin arm64 -output fsmon-ios-arm64
	lipo -create -output fsmon \
		-arch arm64 fsmon-ios-arm64 \
		-arch armv7 fsmon-ios-armv7 \
		-arch armv7k fsmon-wch \
		-arch x86_64 fsmon-osx
	strip fsmon
	codesign -s- fsmon


clean:
	rm -f fsmon-osx fsmon-ios
	rm -rf fsmon*.dSYM

.PHONY: cydia ios osx osx-pkg fat wch

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

NDK_ARCH=arm
ANDROID_ARCHS=arm mips x86
ANDROID_VERSION=kitkat

and android:
	for a in $(ANDROID_ARCHS) ; do \
		$(MAKE) $(ANDROID_VERSION) NDK_ARCH=$$a ; \
	done

ll lollipop:
	./ndk-gcc 21 -fPIC -pie $(LOLLIPOP_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-and-$(NDK_ARCH) \
		main.c os-linux.c util.c

kk kitkat:
	./ndk-gcc 19 -fPIC -pie $(KITKAT_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-kitkat-$(NDK_ARCH) \
		main.c os-linux.c util.c

.PHONY: all fsmon clean
.PHONY: install uninstall
.PHONY: and android ll lollipop kk kitkat
