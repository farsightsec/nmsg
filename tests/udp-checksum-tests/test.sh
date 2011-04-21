#!/usr/bin/env bash

do_directory () {
    dname="$1"
    shift
    expected="$1"
    shift

    for fname in $dname/*; do
        nmsgtool -V ISC -T dnsqr -p $fname | grep "^udp_checksum:" | awk '{print$2}' | \
            while read actual; do
                if [ "$expected" = "$actual" ]; then
                    result="PASS"
                else
                    result="FAIL"
                fi
                echo "$result: [actual=$actual, expected=$expected] $fname"
            done
    done
}

do_directory absent "ABSENT"
do_directory correct "CORRECT"
do_directory incorrect "INCORRECT"
