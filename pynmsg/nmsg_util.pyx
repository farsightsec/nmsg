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
