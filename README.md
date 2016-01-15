fsmon
=====

FileSystem Monitor utility for iOS and OSX

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
	 [path]    only get events from this path
