#!/usr/bin/env python

import nmsg
import socket
import sys
import time

def print_nmsg(m):
    tm = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(m.time_sec))
    sys.stdout.write('[%s.%d] ' % (tm, m.time_nsec))
    sys.stdout.write('[%d:%d %s %s] ' % (m.vid, m.msgtype,
        nmsg.msgmod.vid_to_vname(m.vid), 
        nmsg.msgmod.msgtype_to_mname(m.vid, m.msgtype)))

    if m.has_source:
        sys.stdout.write('[%.8x] ' % m.source)
    else:
        sys.stdout.write('[] ')

    if m.has_operator:
        sys.stdout.write('[%s] ' % m.operator)
    else:
        sys.stdout.write('[] ')

    if m.has_group:
        sys.stdout.write('[%s] ' % m.group)
    else:
        sys.stdout.write('[] ')

    sys.stdout.write('\n')

    for key in m.keys():
        val = m[key]
        for v in val:
            sys.stdout.write('%s: %s\n' % (key, repr(v)))

    sys.stdout.write('\n')

def main(ch):
    io = nmsg.io()
    io.add_input_channel(ch)
    io.add_output_callback(print_nmsg)
    io.loop()

if __name__ == '__main__':
    main(sys.argv[1])
