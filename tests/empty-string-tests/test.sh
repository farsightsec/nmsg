#!/bin/sh

NMSG_MSGMOD_DIR="${top_builddir}/nmsg/base/.libs"
export NMSG_MSGMOD_DIR

NMSGTOOL="${top_builddir}/src/nmsgtool"
TJSON="${top_srcdir}/t/empty-string-tests/empty-string.json"
TNMSG="${top_srcdir}/t/empty-string-tests/empty-string.nmsg"

if $NMSGTOOL -r $TNMSG | fgrep "(null)"; then
    echo FAIL: presentation contains '"(null)"'
else
    echo PASS:
fi

if $NMSGTOOL -j $TJSON | cmp - $TMSG; then
    echo FAIL: json load failed
else
    echo PASS:
fi
