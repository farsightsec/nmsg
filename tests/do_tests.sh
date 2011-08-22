#!/bin/sh

for x in udp-checksum-tests payload-crc32c-tests; do
    echo "executing tests in directory `pwd`/$x"
    sh -c "cd $x && ./test.sh"
done
