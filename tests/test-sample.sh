#!/bin/sh

# This test exercises the sample filter feature of nmsgtool.  Our file has 15
# entries (see $file_entry_count), and we want 5 entries (see $desired_entry_count),
# so we set $sample_entry_count to 3.  We then check to make sure 5 entries were output.

script_dir=$(cd $(dirname "$0") && pwd) # Will be [somedir]/nmsg/tests/
nmsgtool_test=$script_dir/../src/nmsgtool
infile=$script_dir/generic-tests/lorem.json
outfile=/tmp/testsample.json
retval=0

# Our input file has 15 entries, and we want 5 entries to be output.  The sample
# filter will take $sample_entry_count as a parameter to filter every 3 entries
# (resulting in 5 entries output, just like we wanted!).
file_entry_count=15
desired_entry_count=5
sample_entry_count=$((file_entry_count / desired_entry_count))

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		retval=1
	fi
}

echo "Testing sample filter: "

# Create a listener and a writer on the same socket.
$nmsgtool_test -ddddd -F sample,"count=$sample_entry_count" -j $infile -J $outfile

# Verify that the number of entries output is correct.
line_count=$(wc -l $outfile | awk '{print $1}')
[ "$line_count" -eq "$desired_entry_count" ]
check "comparison of sample-filtered json output"

# Cleanup!
rm $outfile

exit $retval
