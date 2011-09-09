#!/usr/bin/env bash

CRC32C_TEST="../../src/crc32c_test"
NMSGTOOL="../../src/nmsgtool"

ERR="^libnmsg: WARNING: crc mismatch"

# test vectors
$CRC32C_TEST

n="CRC32C absent #1"
x="test_crc32c_absent.nmsg"
if $NMSGTOOL -r $x -w /dev/null 2>&1 | grep -q "$ERR"; then
    echo "FAIL: $n"
else
    echo "PASS: $n"
fi

n="CRC32C absent #2"
x="test_crc32c_absent.nmsg"
if $NMSGTOOL -r $x -o /dev/null 2>&1 | grep -q "$ERR"; then
    echo "FAIL: $n"
else
    echo "PASS: $n"
fi

n="CRC32C regeneration #1"
x="test_crc32c_absent.nmsg"
if $NMSGTOOL -r $x -w - | $NMSGTOOL -r - -w /dev/null 2>&1 | grep -q "$ERR"; then
    echo "FAIL: $n"
else
    echo "PASS: $n"
fi

n="CRC32C regeneration #2"
x="test_crc32c_absent.nmsg"
if $NMSGTOOL -r $x -w - | $NMSGTOOL -r - -o /dev/null 2>&1 | grep -q "$ERR"; then
    echo "FAIL: $n"
else
    echo "PASS: $n"
fi

n="CRC32C present and correct #1"
x="test_crc32c_correct.nmsg"
if $NMSGTOOL -r $x -w /dev/null 2>&1 | grep -q "$ERR"; then
    echo "FAIL: $n"
else
    echo "PASS: $n"
fi

n="CRC32C present and correct #2"
x="test_crc32c_correct.nmsg"
if $NMSGTOOL -r $x -o /dev/null 2>&1 | grep -q "$ERR"; then
    echo "FAIL: $n"
else
    echo "PASS: $n"
fi

n="CRC32C present and incorrect #1"
x="test_crc32c_incorrect.nmsg"
if $NMSGTOOL -r test_crc32c_incorrect.nmsg -w /dev/null 2>&1 | grep -q "$ERR"; then
    echo "PASS: $n"
else
    echo "FAIL: $n"
fi

n="CRC32C present and incorrect #2"
x="test_crc32c_incorrect.nmsg"
if $NMSGTOOL -r test_crc32c_incorrect.nmsg -o /dev/null 2>&1 | grep -q "$ERR"; then
    echo "PASS: $n"
else
    echo "FAIL: $n"
fi
