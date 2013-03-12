#!/bin/sh

for x in udp-checksum-tests payload-crc32c-tests; do
    testdir="$(dirname $0)/$x"
    echo "executing tests in directory $testdir"
    sh -c "cd $testdir && ./test.sh"
done
