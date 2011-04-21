#!/bin/sh

echo "executing tests in directory `pwd`/udp-checksum-tests"
sh -c 'cd udp-checksum-tests && ./test.sh'
