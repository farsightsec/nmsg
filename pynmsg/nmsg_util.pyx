cdef class ip(object):
    cdef public str srcip
    cdef public str dstip
    cdef public str payload

    def __init__(self, message msg):
        cdef nmsg_res res
        cdef unsigned etype
        cdef nmsg_ipdg dg

        if msg.vid != 1 or msg.msgtype != 1:
            raise Exception, 'not an ISC/ncap message'

        mtype = msg['type'][0]

        if mtype == 2: # legacy ncap
            self.srcip = msg['srcip']
            self.dstip = msg['dstip']
            self.payload = msg['payload']
        elif mtype == 0 or mtype == 1: # IPv4, IPv6
            if mtype == 0:
                etype = 0x0800 # ETHERTYPE_IP
            elif mtype == 1:
                etype = 0x86dd # ETHERTYPE_IPV6
            res = nmsg_ipdg_parse(&dg, etype, len(msg['payload'][0]), <unsigned char *> PyString_AsString(msg['payload'][0]))
            if res != nmsg_res_success:
                raise Exception, 'nmsg_ipdg_parse() failed'
            self.payload = PyString_FromStringAndSize(<char *> dg.payload, dg.len_payload)

def getsock(str sock):
    addr, port = sock.split('/')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, int(port)))
    return s
