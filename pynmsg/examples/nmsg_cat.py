#!/usr/bin/env python

import nmsg
import sys

n = nmsg.input.open_sock('127.0.0.1', 8430)
o = nmsg.output.open_sock('127.0.0.1', 9430)

print 'starting...'
c = 0
while True:
    c += 1
    if (c % 1000) == 0:
        sys.stderr.write('.')
    if (c % 10000) == 0:
        sys.stderr.write('%s' % c)

    m = n.read()
    o.write(m)
