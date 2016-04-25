#!/bin/sh

# based on
# http://blog.coolaj86.com/articles/how-to-unpackage-and-repackage-pkg-osx.html

# to uninstall:
# sudo pkgutil --forget com.nowsecure.fsmon

SRC=/tmp/r2osx
PREFIX=/usr/local
DST="$(pwd)/fsmon.unpkg"
[ -z "${VERSION}" ] && VERSION=1.1
[ -z "${MAKE}" ] && MAKE=make
VERSION=1.1

rm -rf "${SRC}"
${MAKE} clean
make || exit 1
${MAKE} install PREFIX="${PREFIX}" DESTDIR=${SRC} || exit 1
mkdir -p "${DST}"
if [ -d "${SRC}" ]; then
	(
		cd "${SRC}" && \
		find . | cpio -o --format odc | gzip -c > "${DST}/Payload"
	)
	mkbom "${SRC}" "${DST}/Bom"
	pkgutil --flatten "${DST}" "fsmon-${VERSION}.pkg"
else
	echo "Failed install. DESTDIR is empty"
	exit 1
fi
