ARCHS=armv7 arm64

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
	$(IOS_CC) $(CFLAGS) -o fsmon-ios fsmon.c main.c util.c
	strip fsmon-ios

osx:
	$(CC) $(CFLAGS) -o fsmon-osx fsmon.c main.c util.c
	strip fsmon-osx

wch:
	$(WCH_CC) $(CFLAGS) -o fsmon-wch fsmon.c main.c util.c

fat:
	lipo fsmon-ios -thin armv7 -output fsmon-ios-armv7
	lipo fsmon-ios -thin arm64 -output fsmon-ios-arm64
	lipo -create -output fsmon-fat \
		-arch arm64 fsmon-ios-arm64 \
		-arch armv7 fsmon-ios-armv7 \
		-arch armv7k fsmon-wch \
		-arch x86_64 fsmon-osx
	strip fsmon-fat

clean:
	rm -f fsmon-osx fsmon-ios
	rm -rf fsmon*.dSYM
