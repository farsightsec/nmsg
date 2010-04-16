#!/usr/bin/env python

import nmsg
import socket
import sys

def print_nmsg(m):
    nmsg.print_nmsg_header(m, sys.stdout)

    for key in m.keys():
        val = m[key]
        if type(val) == list:
            for v in val:
                sys.stdout.write('%s: %s\n' % (key, repr(v)))
        else:
            sys.stdout.write('%s: %s\n' % (key, repr(v)))
    sys.stdout.write('\n')

def main(ch):
    io = nmsg.io()
    io.add_input_channel(ch)
    io.add_output_callback(print_nmsg)
    io.loop()

if __name__ == '__main__':
    main(sys.argv[1])
