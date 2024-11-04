#!/bin/sh

# This test daemonizes an nmsgtool and checks its output to make sure it is
# equivalent to the input file.  It also tests the PID functionality present
# in daemon.c.

script_dir=$(cd $(dirname "$0") && pwd) # Will be [somedir]/nmsg/tests/
nmsgtool_test=$script_dir/../src/nmsgtool
infile=$script_dir/generic-tests/lorem.nmsg
outfile=/tmp/testdaemon.nmsg
pidfile=/tmp/testdaemon.pid
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
