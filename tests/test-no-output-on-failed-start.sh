#!/bin/sh

# Copyright (c) 2026 DomainTools LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verify that nmsgtool does not create output files when startup fails before
# any I/O loop begins.  Regression test for the bug where -w/-W/--writejson
# would leave a file behind after a failed channel alias lookup or missing
# input source.

nmsgtool_test=$abs_top_builddir/src/nmsgtool
chalias=$abs_top_srcdir/tests/generic-tests/test.chalias
infile=$abs_top_srcdir/tests/generic-tests/lorem.nmsg
outbase=$abs_top_builddir/tests/test-no-output-on-failed-start
NMSG_MSGMOD_DIR=${NMSG_MSGMOD_DIR:-$abs_top_builddir/nmsg/base/.libs}
retval=0

export NMSG_MSGMOD_DIR

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		retval=1
	fi
}

echo "Testing that no output files are created on failed start:"

# Test 1: -w with no input source — nmsgtool should fail and leave no file.
outfile="${outbase}-no-input.nmsg"
rm -f "$outfile"
$nmsgtool_test -w "$outfile" 2>/dev/null
[ ! -f "$outfile" ]
check "-w leaves no file when no input is specified"

# Test 2: -W with no input source — nmsgtool should fail and leave no file.
outfile="${outbase}-no-input.pres"
rm -f "$outfile"
$nmsgtool_test -W "$outfile" 2>/dev/null
[ ! -f "$outfile" ]
check "-W leaves no file when no input is specified"

# Test 3: -w with a bad channel alias — nmsgtool should fail and leave no file.
outfile="${outbase}-bad-channel.nmsg"
rm -f "$outfile"
NMSG_CHALIAS_FILE="$chalias" $nmsgtool_test -C nosuchchannel -w "$outfile" 2>/dev/null
[ ! -f "$outfile" ]
check "-w leaves no file when channel alias lookup fails"

exit $retval
