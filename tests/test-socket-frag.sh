#!/bin/sh

# This test exercises message fragmentation over a socket by setting the
# maximum transmission unit size to a very low value, then passing a (very large)
# DNSSEC query/response over the socket.  If fragmentation is successful, we will
# have an identical file on the other side!

script_dir=$(cd $(dirname "$0") && pwd) # Will be [somedir]/nmsg/tests/
nmsgtool_test=$script_dir/../src/nmsgtool
infile=$script_dir/generic-tests/dnssec.pcap
outfile_frag=/tmp/testfrag.sock.pres
outfile=/tmp/testfrag.pres
sockaddr=127.0.0.1/8080
entry_count=1
retval=0

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		retval=1
	fi
}

echo "Testing datagram socket fragmentation and reassembly: "

# Write the input file to an nmsg file which will be diffed later.
$nmsgtool_test -ddddd -c $entry_count -p $infile -V base -T dnsqr -o $outfile

# Create a listener, wait a second, then create a writer on the same IP/socket.
$nmsgtool_test -ddddd --unbuffered -m 1 -c $entry_count -o $outfile_frag -l $sockaddr &
listener_pid=$!
sleep 1
$nmsgtool_test -ddddd --unbuffered -m 1 -c $entry_count -p $infile -V base -T dnsqr -s $sockaddr &
writer_pid=$!
echo Listening PID: $listener_pid, writing PID: $writer_pid

# Avert zombie apocalypse
wait $writer_pid
wait $listener_pid

# Verify that there is no difference in the reassembled data vs non-reasm. data.
diff $outfile $outfile_frag
check diff of fragmented vs non-fragmented output

# Clean-up!
rm $outfile
rm $outfile_frag

exit $retval
