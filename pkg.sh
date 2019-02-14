#!/bin/sh

# based on
# http://blog.coolaj86.com/articles/how-to-unpackage-and-repackage-pkg-osx.html

# to uninstall:
# sudo pkgutil --forget com.nowsecure.fsmon

DESTDIR=/tmp/fsmon_pkg
PREFIX=/usr/local
PKGDIR="$(pwd)/fsmon.unpkg"
[ -z "${MAKE}" ] && MAKE=make
. config.mk # VERSION

rm -rf "${DESTDIR}"
${MAKE} clean
make || exit 1
${MAKE} install PREFIX="${PREFIX}" DESTDIR=${DESTDIR} || exit 1
rm -rf "${PKGDIR}"
mkdir -p "${PKGDIR}"

cat > "${PKGDIR}/PackageInfo" << EOF
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<pkg-info overwrite-permissions="true" relocatable="false" identifier="com.nowsecure.fsmon" postinstall-action="none" version="0" format-version="2" generator-version="InstallCmds-237 (11E53)" auth="root">
    <payload numberOfFiles="2" installKBytes="31"/>
    <bundle-version/>
    <upgrade-bundle/>
    <update-bundle/>
    <atomic-update-bundle/>
    <strict-identifier/>
    <relocate/>
</pkg-info>
EOF

if [ -d "${DESTDIR}" ]; then
	(
		cd "${DESTDIR}" && \
		find . | cpio -o --format odc | gzip -c > "${PKGDIR}/Payload"
	)
	mkbom "${DESTDIR}" "${PKGDIR}/Bom"
	pkgutil --flatten "${PKGDIR}" "fsmon-${VERSION}.pkg"
	rm -rf "${DESTDIR}"
	rm -rf "${PKGDIR}"
else
	echo "Failed install. DESTDIR is empty"
	exit 1
fi
