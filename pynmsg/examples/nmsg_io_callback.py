#!/usr/bin/env python

import nmsg
import sys

count = 0

def cb(msg):
    global count
    count += 1
    if (count % 10000) == 0:
        sys.stderr.write('.')

io = nmsg.io()
input = nmsg.input.open_file(sys.argv[1])
io.add_input(input)
io.add_output_callback(cb)
io.add_output_callback(cb)
io.add_output_callback(cb)
io.loop()

print '\ncount=%s' % count
