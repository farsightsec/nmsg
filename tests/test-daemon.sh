#!/bin/sh

# This test daemonizes an nmsgtool and checks its output to make sure it is
# equivalent to the input file.  It also tests the PID functionality present
# in daemon.c.

nmsgtool_test=$abs_top_builddir/src/nmsgtool
infile=$abs_top_srcdir/tests/generic-tests/lorem.nmsg
outfile=$abs_top_builddir/tests/testdaemon.nmsg
pidfile=$abs_top_builddir/tests/testdaemon.pid
retval=0

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		retval=1
	fi
}

echo "Testing nmsgtool daemonization: "

# Start a daemonized nmsgtool and wait for it to finish.
$nmsgtool_test -ddddd -D -r $infile -w $outfile
sleep 1

# Verify that the number of entries output by the daemon is correct.
diff $infile $outfile
check "diff on daemon input vs. output"

# Start a daemonized nmsgtool that outputs a file containing its PID.
$($nmsgtool_test -l 127.0.0.1/12345 -D -P $pidfile)
sleep 1
file_pid=$(cat $pidfile | head -n 1)
proc_pid=$(ps -p `cat $pidfile` | tail -n 1 | awk '{print $1}')

# Compare actual PID with PID in file.
[ "$proc_pid" -eq "$file_pid" ]
check "PID in file ($file_pid) equals actual PID ($proc_pid)"

# Clean up!
kill $proc_pid >/dev/null 2>&1
rm $outfile
rm $pidfile

exit $retval
