include ./CONFIG
DEPENDS=
PACKAGE_DIR?=${PWD}

all:
	$(SUDO) $(MAKE) clean
	mkdir -p data root/usr/bin
	cp -rf ../fsmon-ios root/usr/bin
	$(SUDO) $(MAKE) debroot

clean:
	$(SUDO) $(MAKE) deb_clean

mrproper: clean
	rm -rf root

include deb.mk
