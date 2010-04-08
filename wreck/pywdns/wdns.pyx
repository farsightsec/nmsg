include "wdns.pxi"

QUESTION = 0
ANSWER = 1
AUTHORITY = 2
ADDITIONAL = 3

class WreckException(Exception):
    pass

def domain_to_str(char *src):
    cdef char dst[1025] # WDNS_PRESLEN_NAME
    wdns_domain_to_str(<uint8_t *> src, dst)
    return PyString_FromString(dst)

def str_to_name(char *src):
    cdef wdns_name_t name
    cdef wdns_msg_status status

    status = wdns_str_to_name(src, &name)
    if status != wdns_msg_success:
        raise Exception, 'wdns_str_to_name() failed'
    s = PyString_FromStringAndSize(<char *> name.data, name.len)
    free(name.data)
    return s

def opcode_to_str(uint16_t dns_opcode):
    cdef char *s
    s = wdns_opcode_to_str(dns_opcode)
    if s == NULL:
        return str(dns_opcode)
    return s

def rcode_to_str(uint16_t dns_rcode):
    cdef char *s
    s = wdns_rcode_to_str(dns_rcode)
    if s == NULL:
        return str(dns_rcode)
    return s

def rrclass_to_str(uint16_t dns_class):
    cdef char *s
    s = wdns_rrclass_to_str(dns_class)
    if s == NULL:
        return str(dns_class)
    return s

def rrtype_to_str(uint16_t dns_type):
    cdef char *s
    s = wdns_rrtype_to_str(dns_type)
    if s == NULL:
        return str(dns_type)
    return s

cdef class message(object):
    cdef public int id
    cdef public int flags
    cdef public int rcode
    cdef public int opcode
    cdef public list sec

    cdef public bool qr
    cdef public bool aa
    cdef public bool tc
    cdef public bool rd
    cdef public bool ra
    cdef public bool ad
    cdef public bool cd

    parse = staticmethod(parse_message)

    def __init__(self):
        self.sec = [ [], [], [], [] ]

    def repr_flags(self):
        f = []
        if self.qr:
            f.append('qr')
        if self.aa:
            f.append('aa')
        if self.tc:
            f.append('tc')
        if self.rd:
            f.append('rd')
        if self.ra:
            f.append('ra')
        if self.ad:
            f.append('ad')
        if self.cd:
            f.append('cd')
        return ' '.join(f)

    def __repr__(self):
        s = ';; ->>HEADER<<- opcode: %s, rcode: %s, id: %s\n' % (
            opcode_to_str(self.opcode),
            rcode_to_str(self.rcode),
            self.id
        )
        s += ';; flags: %s; QUERY: %s, ANSWER: %s, AUTHORITY: %s, ADDITIONAL: %s\n''' % (
            self.repr_flags(),
            len(self.sec[0]),
            len(self.sec[1]),
            len(self.sec[2]),
            len(self.sec[3])
        )

        s += '\n;; QUESTION SECTION:\n'
        for dns_rrset in self.sec[0]:
            s += ';%s\n' % dns_rrset

        s += '\n;; ANSWER SECTION:\n'
        for dns_rrset in self.sec[1]:
            s += '%s\n' % dns_rrset

        s += '\n;; AUTHORITY SECTION:\n'
        for dns_rrset in self.sec[2]:
            s += '%s\n' % dns_rrset

        s += '\n;; ADDITIONAL SECTION:\n'
        for dns_rrset in self.sec[3]:
            s += '%s\n' % dns_rrset

        return s

cdef class qrr(object):
    cdef public str name
    cdef public int rrclass
    cdef public int rrtype

    def __repr__(self):
        return '%s %s %s' % (
            domain_to_str(self.name),
            rrclass_to_str(self.rrclass),
            rrtype_to_str(self.rrtype),
        )

cdef class rrset(object):
    cdef public str name
    cdef public int rrclass
    cdef public int rrtype
    cdef public int rrttl
    cdef public list rdata

    def __init__(self):
        self.rdata = []

    def __repr__(self):
        rr = []
        for rd in self.rdata:
            rr.append('%s %s %s %s %s' % (
                domain_to_str(self.name),
                self.rrttl,
                rrclass_to_str(self.rrclass),
                rrtype_to_str(self.rrtype),
                rd
            ))
        return '\n'.join(rr)

cdef class rdata(object):
    cdef public str data
    cdef public int rrclass
    cdef public int rrtype

    def __init__(self, str data, int rrclass, int rrtype):
        self.data = data
        self.rrclass = rrclass
        self.rrtype = rrtype

    def __repr__(self):
        cdef char *dst
        cdef size_t dstsz
        cdef uint8_t *rd
        cdef uint16_t rdlen
        cdef wdns_msg_status status

        if self.data == None:
            raise Exception, 'rdata object not initialized'

        rd = <uint8_t *> PyString_AsString(self.data)
        rdlen = PyString_Size(self.data)

        status = wdns_rdata_to_str(rd, rdlen, self.rrtype, self.rrclass, NULL, &dstsz)
        if status == wdns_msg_success:
            dst = <char *> malloc(dstsz)
            if dst == NULL:
                raise Exception, 'malloc() failed'
            status = wdns_rdata_to_str(rd, rdlen, self.rrtype, self.rrclass, dst, NULL)
            if status != wdns_msg_success:
                raise WreckException('wdns_rdata_to_str() failed')
        else:
            raise WreckException('wdns_rdata_to_str() failed')

        s = PyString_FromString(dst)
        free(dst)
        return s

def parse_message(bytes pkt):
    cdef wdns_message_t m
    cdef wdns_rdata_t *dns_rdata
    cdef wdns_rrset_t *dns_rrset
    cdef wdns_rrset_array_t *a
    cdef wdns_msg_status status
    cdef uint8_t *p

    p = <uint8_t *> PyString_AsString(pkt)
    if p == NULL:
        raise Exception('PyString_AsString() failed')

    status = wdns_parse_message(&m, p, PyString_Size(pkt))
    if status == wdns_msg_success:
        msg = message()
        msg.id = m.id
        msg.flags = m.flags
        msg.rcode = m.rcode
        msg.opcode = (m.flags & 0x7800) >> 11

        if (m.flags >> 15) & 0x01:
            msg.qr = True
        if (m.flags >> 10) & 0x01:
            msg.aa = True
        if (m.flags >> 9) & 0x01:
            msg.tc = True
        if (m.flags >> 8) & 0x01:
            msg.rd = True
        if (m.flags >> 7) & 0x01:
            msg.ra = True
        if (m.flags >> 5) & 0x01:
            msg.ad = True
        if (m.flags >> 4) & 0x01:
            msg.cd = True

        for i from 0 <= i < 4:
            a = &m.sections[i]
            for j from 0 <= j < a.n_rrsets:
                dns_rrset = &a.rrsets[j]
                py_rrset = rrset()

                name = PyString_FromStringAndSize(<char *> dns_rrset[0].name.data, dns_rrset[0].name.len)
                if i == 0:
                    q = qrr()
                    q.name = name
                    q.rrclass = dns_rrset.rrclass
                    q.rrtype = dns_rrset.rrtype
                    msg.sec[0].append(q)
                else:
                    py_rrset.name = name
                    py_rrset.rrclass = dns_rrset.rrclass
                    py_rrset.rrtype = dns_rrset.rrtype
                    py_rrset.rrttl = dns_rrset.rrttl
                    for k from 0 <= k < dns_rrset.n_rdatas:
                        dns_rdata = dns_rrset[0].rdatas[k]
                        py_rdata = PyString_FromStringAndSize(<char *> dns_rdata.data, dns_rdata.len)
                        py_rdata_obj = rdata(py_rdata, dns_rrset.rrclass, dns_rrset.rrtype)
                        py_rrset.rdata.append(py_rdata_obj)
                    msg.sec[i].append(py_rrset)

        wdns_clear_message(&m)
        return msg
    else:
        raise WreckException('wdns_parse_message() returned %s' % status)
