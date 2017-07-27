ARCHS=armv7 arm64

CFLAGS+=-I.
CFLAGS+=-Wall

SOURCES=main.c util.c
SOURCES+=backend/*.c

ifeq ($(shell uname),Linux)
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

all: osx

ios:
	$(IOS_CC) $(CFLAGS) -DTARGET_IOS=1 -o fsmon-ios $(SOURCES) \
		-framework CoreFoundation \
		-framework MobileCoreServices
	strip fsmon-ios
	xcrun --sdk iphoneos codesign -s- fsmon-ios

cydia: ios
	$(MAKE) -C cydia

osx:
	$(CC) $(CFLAGS) -DTARGET_OSX=1 -o fsmon-osx $(SOURCES) -framework CoreServices
	strip fsmon-osx

osx-pkg:
	./pkg.sh

wch:
	$(WCH_CC) $(CFLAGS) -DTARGET_WATCHOS=1 -o fsmon-wch $(SOURCES)

fat: ios osx wch
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

NDK_ARCH=
ANDROID_ARCHS=arm mips x86 x86_64 aarch64
ANDROID_API=

ifneq ($(NDK_ARCH), "")
 ANDROID_ARCHS=$(NDK_ARCH)
endif

and android:
	#export ANDROID_API=$(ANDROID_API)
	for a in $(ANDROID_ARCHS) ; do \
		$(MAKE) andcompile ANDROID_API=$(ANDROID_API) NDK_ARCH=$$a ; \
	done

andcompile:
	if [ $(ANDROID_API) -gt 21 ]; then \
		./ndk-gcc $(ANDROID_API) $(LOLLIPOP_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-and$(ANDROID_API)-$(NDK_ARCH) $(SOURCES) ; \
	else \
		./ndk-gcc $(ANDROID_API) $(KITKAT_CFLAGS) $(CFLAGS) $(LDFLAGS) -o fsmon-and$(ANDROID_API)-$(NDK_ARCH) $(SOURCES) ; \
	fi

.PHONY: all fsmon clean
.PHONY: install uninstall
.PHONY: and android ll lollipop kk kitkat
