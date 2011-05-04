#!/usr/bin/env python

import sys

import nmsg

class UnsupportedEncodeType(Exception):
    pass

class Encode(object):
    __slots__ = ('encode', 'decode')
    def __init__(self, encode, decode):
        self.encode = encode
        self.decode = decode

class EncodeDummy(object):
    @staticmethod
    def encode(*args, **kwargs):
        raise UnsupportedEncodeType
    @staticmethod
    def decode(*args, **kwargs):
        raise UnsupportedEncodeType

try:
    import json
    encode_json = Encode(json.dumps, json.loads)
except ImportError:
    encode_json = EncodeDummy

try:
    import yaml
    encode_yaml = Encode(yaml.dump, yaml.load)
except ImportError:
    encode_yaml = EncodeDummy

try:
    import msgpack
    encode_msgpack = Encode(msgpack.dumps, msgpack.loads)
except ImportError:
    encode_msgpack = EncodeDummy

table_encode = {
    'TEXT':     Encode(str, str),
    'JSON':     encode_json,
    'YAML':     encode_yaml,
    'MSGPACK':  encode_msgpack,
    'XML':      EncodeDummy
}

def process(m):
    nmsg.print_nmsg_header(m, sys.stdout)
    sys.stdout.write('type: %s\n' % m['type'])
    if m['type'] in table_encode:
        try:
            sys.stdout.write('payload: %s' % table_encode[m['type']].decode(m['payload']))
        except UnsupportedEncodeType:
            sys.stdout.write('payload: <UNABLE TO DECODE>')
    else:
        sys.stdout.write('payload: <UNKNOWN ENCODING>')
    sys.stdout.write('\n\n')

def main(addr, port):
    i = nmsg.input.open_sock(addr, port)
    sys.stdout.write('listening on %s/%s\n' % (addr, port))
    while True:
        m = i.read()
        if m:
            process(m)

if __name__ == '__main__':
    if len(sys.argv) == 3:
        main(sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) == 1:
        main('127.0.0.1', 9430)
    else:
        sys.stderr.write('Usage: %s [<ADDR> <PORT>]\n' % sys.argv[0])
        sys.exit(1)
