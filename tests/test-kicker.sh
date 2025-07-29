#!/bin/sh

# This test exercises the kicker script functionality by reading in sample data
# containing 15 (defanged) ch202 entries and writing them each to a separate file
# in a temporary directory.  For each file, we echo its name into test-kicker.out
# (followed by a newline), and remove it.  Once all files have been kicked
# (resulting in 15 lines in test-kicker.out) the total line count must equal 15.

nmsgtool_test=$abs_top_builddir/src/nmsgtool
infile=$abs_top_srcdir/tests/generic-tests/lorem.json
outdir=$abs_top_builddir/tests/test-kicker/ # This directory will get rm -rf'd; be careful!
outfile=$outdir/test-kicker.out
# by using echo as the kicker the filenames are output one at a time to stdout
kicker="echo"
retval=0

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		retval=1
	fi
}

echo "Testing kicker: "

mkdir $outdir
cd $outdir
NMSG_MSGMOD_DIR=${NMSG_MSGMOD_DIR:-$abs_top_builddir/nmsg/base/.libs}

# Read input data with our kicked nmsgtools.
$nmsgtool_test -ddddd -j $infile -c 1 -k "$kicker" > $outfile

# Compare echo'd file count and actual file count with the desired file count.
file_count=$(wc -l $outfile | awk '{print $1}')
true_file_count=$(ls -1 $outdir | wc -l)
[ "$file_count" -eq "15" ] && [ "$true_file_count" -eq "16" ] # 16 to account for output file.
check "comparison of kicked output files"

# Remove kicked files from $outdir.
while IFS= read -r line; do
	rm $line
done < $outfile

# If every kicked filename was correctly written to the kicker file, then only
# one file will be left in $outdir.
file_count=$(ls -1 $outdir | wc -l)
[ "$file_count" -eq "1" ] # 1 to account for the kicker output file.
check "file names in kicker output file match actual output filenames"

# Clean-up!
rm -rf $outdir

exit $retval
