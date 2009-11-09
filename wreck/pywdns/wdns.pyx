include "wdns.pxi"

def WreckException(Exception):
    pass

def domain_to_str(char *src):
    cdef char *dst
    dst = <char *> malloc(len(src) + 1)
    wdns_domain_to_str(<uint8_t *> src, dst)
    return dst

def parse_message(bytes pkt):
    cdef wdns_message_t m
    cdef wdns_rdata_t *rdata
    cdef wdns_rrset_t *rrset
    cdef wdns_rrset_array_t *a
    cdef wdns_msg_status status
    cdef uint8_t *p

    p = <uint8_t *> PyString_AsString(pkt)
    if p == NULL:
        raise Exception('PyString_AsString() failed')

    status = wdns_parse_message(&m, p, PyString_Size(pkt))
    if status == wdns_msg_success:
        secs = [ [], [], [], [] ]
        for i from 0 <= i < 4:
            a = &m.sections[i]
            for j from 0 <= j < a.n_rrsets:
                rrset = &a.rrsets[j]
                name = PyString_FromStringAndSize(<char *> rrset[0].name.data, rrset[0].name.len)
                if i == 0:
                    secs[i].append((name, rrset.rrclass, rrset.rrtype))
                else:
                    rdata_list = []
                    for k from 0 <= k < rrset.n_rdatas:
                        rdata = rrset[0].rdatas[k]
                        py_rdata = PyString_FromStringAndSize(<char *> rdata.data, rdata.len)
                        rdata_list.append(py_rdata)
                    secs[i].append((name, rrset.rrclass, rrset.rrtype, rrset.rrttl, rdata_list))

        wdns_clear_message(&m)
        return (m.id, m.flags, m.rcode, secs[0], secs[1], secs[2], secs[3])
    else:
        raise WreckException('wdns_parse_message() returned %s' % status)
