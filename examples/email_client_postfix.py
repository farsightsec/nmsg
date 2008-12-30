#!/usr/bin/env python

from subprocess import Popen, PIPE
import os
import sys

nmsgtool = 'nmsgtool -c 1 -V ISC -T email -f - -s 127.0.0.1/8430'

srcip = os.getenv('CLIENT_ADDRESS')
srchost = os.getenv('CLIENT_HOSTNAME')
helo = os.getenv('CLIENT_HELO')
fro = os.getenv('SENDER')
rcpt = os.getenv('ORIGINAL_RECIPIENT')

headers = []

for line in sys.stdin:
    if line == '\n':
        break
    headers.append(line.strip('\n'))

headers = '\n'.join(headers)

p = Popen(nmsgtool, shell=True, stdin=PIPE)

if srcip:
    p.stdin.write('srcip: %s\n' % srcip)
if srchost:
    p.stdin.write('srchost: %s\n' % srchost)
if helo:
    p.stdin.write('helo: %s\n' % helo)
if fro:
    p.stdin.write('from: %s\n' % fro)
if rcpt:
    p.stdin.write('rcpt: %s\n' % rcpt)
if headers:
    p.stdin.write('headers:\n%s\n.\n\n' % headers)

p.stdin.close()
p.wait()
