fsmon
=====

FileSystem Monitor utility that runs on Linux, Android, iOS and OSX.

Brought to you by Sergi Àlvarez at Nowsecure and distributed under the MIT license.

Contact: pancake@nowsecure.com

Usage
-----

The tool retrieves file system events from a specific directory and shows them in colorful format or in JSON.

It is possible to filter the events happening from a specific program name or process id (PID).

	Usage: ./fsmon [-jc] [-a sec] [-b dir] [-B name] [-p pid] [-P proc] [path]
	 -a [sec]  stop monitoring after N seconds (alarm)
	 -b [dir]  backup files to DIR folder (EXPERIMENTAL)
	 -B [name] specify an alternative backend
	 -c        follow children of -p PID
	 -f        show only filename (no path)
	 -h        show this help
	 -j        output in JSON format
	 -L        list all filemonitor backends
	 -p [pid]  only show events from this pid
	 -P [proc] events only from process name
	 -v        show version
	 [path]    only get events from this path

Compilation
-----------

fsmon is a portable tool. It works on iOS, OSX, Linux and Android (x86, arm, arm64, mips)

*Linux*

	$ make

*OSX + iOS fatbin*

	$ make

*iOS*

	$ make ios

*Android*

	$ make android NDK_ARCH=arm

To get fsmon installed system wide just type:

	$ make install
