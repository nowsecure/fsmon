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
	$(CC) -o fsmon $(CFLAGS) $(LDFLAGS) fsmon-linux.c main.c util.c

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
	$(IOS_CC) $(CFLAGS) -o fsmon-ios fsmon-darwin.c main.c util.c
	strip fsmon-ios
	xcrun --sdk iphoneos codesign -s- fsmon-ios

cydia: ios
	$(MAKE) -C cydia

osx:
	$(CC) $(CFLAGS) -o fsmon-osx fsmon-darwin.c main.c util.c
	strip fsmon-osx

wch:
	$(WCH_CC) $(CFLAGS) -o fsmon-wch fsmon-darwin.c main.c util.c

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

.PHONY: cydia ios osx fat wch

endif

install:
	install -m 0755 fsmon /usr/local/bin/fsmon
	install -m 0644 fsmon.1 $(DESTDIR)$(PREFIX)/share/man/man1/fsmon.1

uninstall:
	rm -f /usr/local/bin/fsmon
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/fsmon.1

# ANDROID
#
# \.-----./
# / o   o \
# `-------'
LOLLIPOP_CFLAGS=-DHAVE_FANOTIFY=1 -DHAVE_SYS_FANOTIFY=0
KITKAT_CFLAGS=-DHAVE_FANOTIFY=0 -DHAVE_SYS_FANOTIFY=0

android: lollipop

lollipop:
	./ndk-gcc 21 -fPIC -pie $(LOLLIPOP_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-and \
		main.c fsmon-linux.c util.c

kitkat:
	./ndk-gcc 19 -fPIC -pie $(KITKAT_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-and \
		main.c fsmon-linux.c util.c

.PHONY: android lollipop kitkat
.PHONY: install uninstall
.PHONY: all fsmon clean
