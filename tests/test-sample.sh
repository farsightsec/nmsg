#!/bin/sh

# This test exercises the sample filter feature of nmsgtool.  Our file has 15
# entries (see $file_entry_count), and we want 5 entries (see $desired_entry_count),
# so we set $sample_entry_count to 3.  We then check to make sure 5 entries were output.

nmsgtool_test=$abs_top_builddir/src/nmsgtool
infile=$abs_top_srcdir/tests/generic-tests/lorem.json
outfile=$abs_top_builddir/tests/testsample.json
NMSG_FLTMOD_VERSION=`awk '/^\#define NMSG_FLTMOD_VERSION/ { print $NF}' < $abs_top_srcdir/nmsg/fltmod_plugin.h`
NMSG_MODULE_SUFFIX=`awk '/^\#define NMSG_MODULE_SUFFIX/ { print $NF}' < $abs_top_srcdir/nmsg/private.h | tr -d '"'`
MODULE_PATHNAME=$abs_top_builddir/fltmod/.libs/nmsg_flt${NMSG_FLTMOD_VERSION}_sample${NMSG_MODULE_SUFFIX}
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
$nmsgtool_test -ddddd -F ${MODULE_PATHNAME},"count=$sample_entry_count" -j $infile -J $outfile

# Verify that the number of entries output is correct.
line_count=$(wc -l $outfile | awk '{print $1}')
[ "$line_count" -eq "$desired_entry_count" ]
check "comparison of sample-filtered json output"

# Cleanup!
rm $outfile

exit $retval
