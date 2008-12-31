#!/usr/bin/env python

from subprocess import Popen, PIPE
import email
import os
import re
import sys

# pick one of 'unknown', 'spamtrap', 'rej_network', 'rej_content', 'rej_user'
email_type = 'unknown'

nmsgtool = 'nmsgtool -c 1 -V ISC -T email -f - -s 127.0.0.1/8430'

urlRE = re.compile('(https?://\\S+?)(?:[\\s\'"<>\(\)\[\]])')

def main():
    srcip = os.getenv('CLIENT_ADDRESS')
    srchost = os.getenv('CLIENT_HOSTNAME')
    helo = os.getenv('CLIENT_HELO')
    fro = os.getenv('SENDER')
    rcpt = os.getenv('ORIGINAL_RECIPIENT')

    rawmsg = sys.stdin.read()
    headers = rawmsg.split('\n\n', 1)[0]
    headers.replace('\n.\n', '\n..\n')
    urls = extract_urls(rawmsg)

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
    for url in urls:
        p.stdin.write('bodyurl: %s\n' % url)
    if headers:
        p.stdin.write('headers:\n%s' % headers)
        if headers[-1] != '\n':
            p.stdin.write('\n')
        p.stdin.write('.\n')
    p.stdin.write('\n\n')

    p.stdin.close()
    p.wait()

def extract_urls(rawmsg):
    urlset = set()
    msg = email.message_from_string(rawmsg)
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        payload = part.get_payload(decode=True)
        if payload:
            for match in urlRE.findall(payload):
                urlset.add(match)
    urls = list(urlset)
    urls.sort()
    return urls

if __name__ == '__main__':
    main()
