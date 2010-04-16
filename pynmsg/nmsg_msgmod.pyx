def msgmod_get_max_msgtype(unsigned vid):
    cdef char *vname
    vname = nmsg_msgmod_vid_to_vname(vid)
    if vname == NULL:
        raise Exception, 'unknown vendor ID'
    else:
        return nmsg_msgmod_get_max_msgtype(vid)

def msgmod_vid_to_vname(unsigned vid):
    cdef char *vname
    vname = nmsg_msgmod_vid_to_vname(vid)
    if vname == NULL:
        raise Exception, 'unknown vendor ID'
    else:
        return str(vname)

def msgmod_vname_to_vid(char *vname):
    cdef unsigned vid
    vid = nmsg_msgmod_vname_to_vid(vname)
    if vid == 0:
        raise Exception, 'unknown vendor name'
    return vid

def msgmod_msgtype_to_mname(unsigned vid, unsigned msgtype):
    cdef char *mname
    mname = nmsg_msgmod_msgtype_to_mname(vid, msgtype)
    if mname == NULL:
        raise Exception, 'unknown message type'
    else:
        return str(mname)

def msgmod_mname_to_msgtype(unsigned vid, char *mname):
    cdef unsigned msgtype
    msgtype = nmsg_msgmod_mname_to_msgtype(vid, mname)
    if msgtype == 0:
        raise Exception, 'unknown vendor ID or message type name'
    return msgtype

cdef class msgmod(object):
    cdef unsigned _vid
    cdef unsigned _msgtype
    cdef void *_clos
    cdef nmsg_msgmod_t _instance

    get_max_msgtype = staticmethod(msgmod_get_max_msgtype)
    vid_to_vname = staticmethod(msgmod_vid_to_vname)
    vname_to_vid = staticmethod(msgmod_vname_to_vid)
    msgtype_to_mname = staticmethod(msgmod_msgtype_to_mname)
    mname_to_msgtype = staticmethod(msgmod_mname_to_msgtype)

    def __cinit__(self, unsigned vid, unsigned msgtype):
        cdef nmsg_res

        self._instance = nmsg_msgmod_lookup(vid, msgtype)
        if self._instance != NULL:
            res = nmsg_msgmod_init(self._instance, &self._clos)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_msgmod_init() failed'
        else:
            raise Exception, 'nmsg_msgmod_lookup() failed'

        self._vid = vid
        self._msgtype = msgtype

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_msgmod_fini(self._instance, &self._clos)

    def __str__(self):
        return '[%d:%d %s %s] message module' % (
            self._vid,
            self._msgtype,
            msgmod_vid_to_vname(self._vid),
            msgmod_msgtype_to_mname(self._vid, self._msgtype)
        )
