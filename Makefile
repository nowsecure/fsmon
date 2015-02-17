IOS_CC=$(shell xcrun --sdk iphoneos --find clang) -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -arch armv7 -arch armv7s -arch arm64
# -arch x86_64
CC?=gcc
CFLAGS+=-g -ggdb

OBJS=fsmon.o main.o

all: ios osx
	#scp fsmon-ios root@192.168.1.50:.

ios:
	$(IOS_CC) $(CFLAGS) -o fsmon-ios fsmon.c main.c util.c

osx:
	$(CC) $(CFLAGS) -o fsmon-osx fsmon.c main.c util.c

clean:
	rm -f fsmon-osx fsmon-ios
	rm -rf fsmon*.dSYM
