#!/usr/bin/env python

import nmsg

o = nmsg.output.open_sock('127.0.0.1', 9430)

m = nmsg.msgtype.isc.ipconn()

for i in range(0, 100):
    m['srcip'] = '127.0.0.%s' % i
    m['dstip'] = '127.1.0.%s' % i
    m['srcport'] = i
    m['dstport'] = 65535 - i
    o.write(m)
