#!/usr/bin/env python

import select
import sys

import nmsg

def main(ip, port):
    ni = nmsg.input.open_sock(ip, port)
    fd = ni.fileno()

    p = select.poll()
    p.register(fd, select.POLLIN)

    while True:
        events = p.poll(1000)
        if events:
            m = ni.read()
            while m:
                print 'got a message'
                m = ni.read()
        else:
            print 'no messages!'

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
