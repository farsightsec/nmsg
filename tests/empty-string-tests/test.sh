#!/bin/sh

if [ -z "${top_srcdir}" ]; then
    echo "top_srcdir variable not set"
    exit 1
fi

if [ -z "${top_builddir}" ]; then
    echo "top_builddir variable not set"
    exit 1
fi

NMSG_MSGMOD_DIR="${top_builddir}/nmsg/base/.libs"
export NMSG_MSGMOD_DIR

NMSGTOOL="${top_builddir}/src/nmsgtool"
TJSON="${top_srcdir}/tests/empty-string-tests/empty-string.json"
TNMSG="${top_srcdir}/tests/empty-string-tests/empty-string.nmsg"

if $NMSGTOOL -r $TNMSG | fgrep "(null)"; then
    echo FAIL: presentation contains '"(null)"'
    exit 1
else
    echo PASS: presentation format empty
fi

if $NMSGTOOL -j $TJSON -w - | cmp - $TNMSG; then
    echo PASS: json load succeeded
else
    echo FAIL: json load failed
    exit 1
fi
