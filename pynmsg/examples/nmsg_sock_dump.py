#!/usr/bin/env python

import nmsg
import socket
import sys
import time

def main(addr, port, out):
    i = nmsg.input.open_sock(addr, port)

    while True:
        m = i.read()
        if not m:
            break

        nmsg.print_nmsg_header(m, out)

        for key in m.keys():
            val = m[key]
            for v in val:
                out.write('%s: %s\n' % (key, repr(v)))
        out.write('\n')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.stdout)
