#!/bin/sh
# android shell script by pancake

if [ -n "$1" ]; then
	NDK_ARCH="$1"
	shift
fi
export ANDROID=1
case "${NDK_ARCH}" in
mips64)
	export NDK_ARCH
	AR=mips64el-linux-android-ar
	RANLIB=mips64el-linux-android-ranlib
	;;
mips)
	export NDK_ARCH
	AR=mipsel-linux-android-ar
	RANLIB=mipsel-linux-android-ranlib
	;;
x86_64|x86)
	export NDK_ARCH
	;;
aarch64|arm64)
	NDK_ARCH=arm64
	export NDK_ARCH
	AR=aarch64-linux-android-ar
	RANLIB=aarch64-linux-android-ranlib
	;;
arm)
	export NDK_ARCH
	AR=arm-linux-androideabi-ar
	RANLIB=arm-linux-androideabi-ranlib
	;;
local)
	export ANDROID=1
	;;
*)
	echo "Usage: $0 [arm64|arm|mips|mips64|x86]"
	exit 1
	;;
esac

LANG=C
export LANG
ROOT=`dirname $0`
OS=`uname|tr 'A-Z' 'a-z'`
[ "${OS}" = macosx ] && OS=darwin

if [ ! -x /work ]; then
	echo "Building android locally with NDK instead of dockcross..."
	# TODO: autodetect or gtfo
	if [ -f ~/.r2androidrc ]; then
		. ~/.r2androidrc
		echo "Using data from ${HOME}/.r2androidrc.."
	else
		#[ -z "${SDK}" ] && SDK="${HOME}/Downloads/android-sdk-${OS}"
		if [ -z "${NDK}" ]; then
			# Checking if Android NDK is installed with macOS's brew
			D=/usr/local/Caskroom/android-ndk/
			if [ -d "${D}" ]; then
				for a in $(cd "$D" && ls) ; do
					N="$D/$a/android-ndk-r$a"
					if [ -f "$N/README.md" ]; then
						NDK="$N"
						break
					fi
				done
			fi
		fi
		if [ -z "${NDK}" ]; then
			if [ ! -d ~/Downloads ]; then
				echo "Set NDK env var or download it in ~/Download"
			fi
			for a in ~/Downloads/android-ndk-* ; do
				if [ -f "$a/README.md" ]; then
					NDK="$a"
					break
				fi
			done
			if [ -z "${NDK}" ]; then
				echo "Invalid path in NDK environment, please change me."
				exit 1
			fi
			echo "Using ${NDK} as NDK path."
		fi
		if [ -z "${NDK}" ]; then
			if [ "`uname`" = "Darwin" ]; then
				NDK="${HOME}/Library/Android/sdk/ndk-bundle/"
			else
				NDK="${HOME}/Downloads/android-ndk-r7b"
			fi
		fi
		[ -z "${NDK}" ] && NDK="${HOME}/Downloads/android-ndk-r7b"
	fi
fi

echo ROOT=$ROOT
echo NDK=$NDK
echo NDK_ARCH=$NDK_ARCH

echo "Building the standalone NDK toolchain..."
"${NDK}/build"/tools/make_standalone_toolchain.py --arch=${NDK_ARCH} --install-dir=/tmp/ndk/ --api=28 --force
if [ $? != 0 ]; then
	exit 1
fi
(
cd /tmp/ndk/bin/ && \
ln -fs clang ndk-gcc && \
ln -fs clang++ ndk-g++
)
if [ "${BUILD}" != 0 ]; then
	if [ ! -d "${NDK}" ]; then
		echo "Cannot find Android NDK ${NDK}" >&2
		echo "echo NDK=/path/to/ndk > ~/.r2androidrc" >&2
		exit 1
	fi
	PATH=/tmp/ndk/bin:$PATH
	export PATH
	export CFLAGS
	export NDK
	export NDK_ARCH
	[ -z "${SHELL}" ] && SHELL=sh
	SHELL=sh
	CC=ndk-gcc
	CXX=ndk-g++
	PS1="[android-ndk-${NDK_ARCH}]> "
	export CC
	export CXX
	export PS1
	export AR
	export RANLIB
	A="$@"
	if [ -n "$A" ]; then
		${SHELL} -c "$A"
	else
		${SHELL}
	fi
fi
