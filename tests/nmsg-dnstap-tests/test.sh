#!/bin/sh

status=0

check() {
	if [ $? = "0" ]; then
		echo "PASS: $*"
	else
		echo "FAIL: $*"
		status=1
	fi
}

NMSG_MSGMOD_DIR="../../nmsg/base/.libs"
export NMSG_MSGMOD_DIR
NMSGTOOL="../../src/nmsgtool"

$NMSGTOOL -r test.nmsg | fgrep -q "message_type: RESOLVER_RESPONSE"
check message_type

$NMSGTOOL -r test.nmsg | fgrep -q "response_address: 192.31.80.30"
check response_address

$NMSGTOOL -r test.nmsg | fgrep -q "query_zone: com."
check query_zone 

$NMSGTOOL -r test.nmsg | fgrep -q "response_message: [406 octets]"
check response_message

$NMSGTOOL -r test.nmsg | fgrep -q "qname: www.farsightsecurity.com."
check response_message

exit $status
