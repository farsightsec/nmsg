#!/bin/sh

# This test exercises various base message modules by writing them out to .json
# files and comparing the number of entries.

nmsgtool_test=$abs_top_builddir/src/nmsgtool
indir=$abs_top_srcdir/tests/generic-tests/
# this directory is created and removed:
outdir=$abs_top_builddir/tests/test-msgmod/
retval=0

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		retval=1
	fi
}

# Param. 1 is message type, param. 2 is input .pcap file name, and param. 3 is the expected final entry count.
run_nmsgtools() {
	nmsgout=test-$1.nmsg
	jsonout=test-$1.json

	$nmsgtool_test -ddddd -p $indir/$2 -V base -T $1 -w $outdir/$nmsgout
	$nmsgtool_test -ddddd -r $outdir/$nmsgout -J $outdir/$jsonout

	line_count=$(wc -l $outdir/$jsonout | awk '{print $1}')
	[ "$line_count" -eq "$3" ]
	check "base/$1 pcap message parsing ($line_count/$3 payloads parsed)"
}

echo "Testing message modules: "

mkdir $outdir

# Test message modules (setting a few environment variables to increase coverage).
export DNSQR_FILTER_QNAMES_EXCLUDE="docusign.com."
run_nmsgtools dnsqr dig_response.pcap 0

export DNSQR_ZERO_RESOLVER_ADDRESS="1"
export DNSQR_FILTER_QNAMES_INCLUDE="docusign.com."
run_nmsgtools dnsqr dig_response.pcap 6
zeroed_resolver_addresses=$(grep -o "\"resolver_address_zeroed\":true" $abs_top_builddir/tests/test-msgmod/test-dnsqr.json | wc -l)
[ "$zeroed_resolver_addresses" -eq "6" ]
check "zeroed DNSQR resolver addresses"

run_nmsgtools pkt http_response.pcap 10
run_nmsgtools packet http_response.pcap 10

# Clean-up!
rm -rf $outdir

exit $retval
