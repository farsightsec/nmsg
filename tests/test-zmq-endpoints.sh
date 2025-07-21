#!/bin/sh

# This script sets up 2 nmsgtools: A ZMQ listener and a ZMQ writer.  The
# writer attempts to write $entry_count entries to a ZMQ socket which the listener
# is listening on.  If, at the end of the test, we do not have the correct
# number of entries in the listener's output file, then we fail.

nmsgtool_test=$abs_top_builddir/src/nmsgtool
infile=$abs_top_srcdir/tests/generic-tests/lorem.nmsg
outfile=$abs_top_builddir/tests/testzmq.json
sock=$abs_top_builddir/tests/testzmq.sock
entry_count=15
retval=0

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		retval=1
	fi
}

echo "Testing ZMQ socket connection: "

# Create a listener and a writer on the same socket.
$nmsgtool_test -ddddd --unbuffered -J $outfile -L ipc://$sock,pushpull,connect &
listener_pid=$!
$nmsgtool_test -ddddd --unbuffered -r $infile -S ipc://$sock,pushpull,accept &
writer_pid=$!
echo Listening PID: $listener_pid, writing PID: $writer_pid

# Wait for the messages to send/receive.
sleep 1

# Kill em all!
kill $writer_pid >/dev/null 2>&1
kill $listener_pid >/dev/null 2>&1

# Verify that the number of entries output is correct.
line_count=$(wc -l $outfile | awk '{print $1}')
[ "$line_count" -eq "$entry_count" ]
check "comparison of json output"

# Cleanup!
exit $retval
