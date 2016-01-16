fsmon
=====

FileSystem Monitor utility that runs on Linux, Android, iOS and OSX.

Brought to you by Sergi Àlvarez at Nowsecure and distributed under the MIT license.

Contact: pancake@nowsecure.com

Usage
-----

The tool retrieves file system events from a specific directory and shows them in colorful format or in JSON.

It is possible to filter the events happening from a specific program name or process id (PID).

	$ ./fsmon -h
	Usage: ./fsmon [-jc] [-a sec] [-b dir] [-p pid] [-P proc] [path]
	 -a [sec]  stop monitoring after N seconds (alarm)
	 -b [dir]  backup files to DIR folder (EXPERIMENTAL)
	 -c        follow children of -p PID
	 -h        show this help
	 -j        output in JSON format
	 -f        show only filename (no path)
	 -p [pid]  only show events from this pid
	 -P [proc] events only from process name
	 -v        show version
	 [path]    only get events from this path

Compilation
-----------

fsmon is a portable tool. It works on iOS, OSX, Linux and Android (x86, arm, arm64, mips)

* Linux

	linux$ make

* OSX + iOS fatbin

	osx$ make

* Android

	$ make android NDK_ARCH=arm

in order to get fsmon installed system wide just use:

	$ make install
