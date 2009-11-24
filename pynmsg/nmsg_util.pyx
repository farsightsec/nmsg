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

        if mtype == 2: # legacy ncap
            self.srcip = msg['srcip']
            self.dstip = msg['dstip']
            self.payload = msg['payload']
        elif mtype == 0 or mtype == 1: # IPv4, IPv6
            if mtype == 0:
                etype = 0x0800 # ETHERTYPE_IP
            elif mtype == 1:
                etype = 0x86dd # ETHERTYPE_IPV6
            res = nmsg_ipdg_parse(&dg, etype, len(msg['payload']), <unsigned char *> PyString_AsString(msg['payload']))
            if res != nmsg_res_success:
                raise Exception, 'nmsg_ipdg_parse() failed'
            self.payload = PyString_FromStringAndSize(<char *> dg.payload, dg.len_payload)

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
