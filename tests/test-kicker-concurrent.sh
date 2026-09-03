#!/bin/sh

nmsgtool=$abs_top_builddir/src/nmsgtool
sample=$abs_top_srcdir/tests/generic-tests/lorem.json
outdir=$abs_top_builddir/tests/test-kicker-concurrent/
mkdir -p "$outdir"; cd "$outdir"

for i in 1 2 3 4 5 6 7 8; do cp "$sample" "in$i.json"; done

TSAN_OPTIONS="halt_on_error=1 exitcode=99" \
"$nmsgtool" -ddd \
    -j in1.json -j in2.json -j in3.json -j in4.json \
    -j in5.json -j in6.json -j in7.json -j in8.json \
    -c 1 -k "echo" -w out > kicked.list 2>run.log
rc=$?

[ $rc -ne 99 ] || { echo "FAIL: race condition "; cat run.log; exit 1; }
[ $rc -eq 0 ]  || { echo "FAIL: nmsgtool exit $rc";  cat run.log; exit 1; }

files=$(wc -l < kicked.list)
[ "$files" -ge 100 ] || { echo "FAIL: only $files rotations"; exit 1; }
echo PASS
