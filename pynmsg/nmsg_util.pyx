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

        mtype = msg['type']

        if mtype == 'Legacy':
            self.srcip = msg['srcip']
            self.dstip = msg['dstip']
            self.payload = msg['payload']
        elif mtype == 'IPV4' or mtype == 'IPV6':
            if mtype == 'IPV4':
                etype = 0x0800 # ETHERTYPE_IP
            elif mtype == 'IPV6':
                etype = 0x86dd # ETHERTYPE_IPV6
            res = nmsg_ipdg_parse(&dg, etype, len(msg['payload']), <unsigned char *> PyString_AsString(msg['payload']))
            if res != nmsg_res_success:
                raise Exception, 'nmsg_ipdg_parse() failed'
            self.payload = PyString_FromStringAndSize(<char *> dg.payload, dg.len_payload)
            iphdr = PyString_FromStringAndSize(<char *> dg.network, dg.len_network)
            if mtype == 'IPV4':
                if len(iphdr) < 20:
                    raise Exception, 'malformed IPv4 header'
                self.srcip = socket.inet_ntop(socket.AF_INET, iphdr[12:16])
                self.dstip = socket.inet_ntop(socket.AF_INET, iphdr[16:20])
            elif mtype == 'IPV6':
                if len(iphdr) < 40:
                    raise Exception, 'malformed IPv6 header'
                self.srcip = socket.inet_ntop(socket.AF_INET6, iphdr[8:24])
                self.dstip = socket.inet_ntop(socket.AF_INET6, iphdr[24:40])
        else:
            raise Exception, 'unknown type: %s' % mtype

    def __repr__(self):
        return 'srcip=%s dstip=%s payload=%s' % (self.srcip, self.dstip, repr(self.payload))

def ip_pton(ip):
    try:
        return socket.inet_pton(socket.AF_INET, ip)
    except:
        return socket.inet_pton(socket.AF_INET6, ip)

def print_nmsg_header(m, out):
    tm = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(m.time_sec))
    out.write('[%s.%d] ' % (tm, m.time_nsec))
    out.write('[%d:%d %s %s] ' % (m.vid, m.msgtype,
        msgmod.vid_to_vname(m.vid),
        msgmod.msgtype_to_mname(m.vid, m.msgtype)))

    if m.has_source:
        out.write('[%.8x] ' % m.source)
    else:
        out.write('[] ')

    if m.has_operator:
        out.write('[%s] ' % m.operator)
    else:
        out.write('[] ')

    if m.has_group:
        out.write('[%s] ' % m.group)
    else:
        out.write('[] ')

    out.write('\n')
