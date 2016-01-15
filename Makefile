ARCHS=armv7 arm64

IOS_ARCHS=$(addprefix -arch ,$(ARCHS))
IOS_CFLAGS+=$(IOS_ARCHS)
IOS_SYSROOT=$(shell xcrun --sdk iphoneos --show-sdk-path)
IOS_CFLAGS+=-isysroot ${IOS_SYSROOT}
IOS_CFLAGS+=-fembed-bitcode
IOS_CFLAGS+=-flto
IOS_CFLAGS+=-O3
IOS_CC=$(shell xcrun --sdk iphoneos --find clang) $(IOS_CFLAGS)

CC?=gcc
CFLAGS+=-g -ggdb

OBJS=fsmon.o main.o

all: ios osx
	$(MAKE) fat
	#scp fsmon-ios root@192.168.1.50:.

ios:
	$(IOS_CC) $(CFLAGS) -o fsmon-ios fsmon.c main.c util.c
	strip fsmon-ios

osx:
	$(CC) $(CFLAGS) -o fsmon-osx fsmon.c main.c util.c
	strip fsmon-osx

fat:
	lipo fsmon-ios -thin armv7 -output fsmon-ios-armv7
	lipo fsmon-ios -thin arm64 -output fsmon-ios-arm64
	lipo -create -output fsmon-fat \
		-arch arm64 fsmon-ios-arm64 \
		-arch armv7 fsmon-ios-armv7 \
		-arch x86_64 fsmon-osx
	strip fsmon-fat

clean:
	rm -f fsmon-osx fsmon-ios
	rm -rf fsmon*.dSYM
