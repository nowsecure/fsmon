include ./CONFIG
DEPENDS=
PACKAGE_DIR?=${PWD}

all:
	$(SUDO) $(MAKE) mrproper
	mkdir -p data root/usr/bin
	cp -f ../../fsmon-ios root/usr/bin/fsmon
	mkdir -p root/usr/share/man/man1
	cp -f ../../fsmon.1 root/usr/share/man/man1/fsmon.1
	$(SUDO) $(MAKE) debroot

clean:
	$(SUDO) $(MAKE) deb_clean

mrproper: clean
	rm -rf root

include deb.mk
