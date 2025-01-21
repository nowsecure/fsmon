include ./CONFIG
DEPENDS=
PACKAGE_DIR?=$(shell pwd)

all: arm64 arm

arm: 
	$(MAKE) ARCH=iphoneos-arm USR_PATH=usr target

arm64: 
	$(MAKE) ARCH=iphoneos-arm64 USR_PATH=var/jb/usr target
	
target:
	$(SUDO) $(MAKE) mrproper
	mkdir -p data root/${USR_PATH}/bin out
	$(MAKE) -C ../.. ios
	cp -f ../../fsmon-ios root/${USR_PATH}/bin/fsmon
	chmod +x root/${USR_PATH}/bin/fsmon
	mkdir -p root/${USR_PATH}/share/man/man1
	cp -f ../../fsmon.1 root/${USR_PATH}/share/man/man1/fsmon.1
	$(SUDO) $(MAKE) ARCH=${ARCH} debroot
	cp *.deb out

clean:
	$(SUDO) $(MAKE) deb_clean

mrproper: clean
	rm -rf root

include deb.mk
