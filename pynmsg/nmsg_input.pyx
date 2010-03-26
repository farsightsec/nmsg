def input_open_file(obj):
    if type(obj) == str:
        obj = open(obj)
    i = input()
    i._open_file(obj)
    return i

def input_open_sock(addr, port):
    obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    obj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    obj.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1048576)
    obj.bind((addr, int(port)))
    i = input()
    i._open_sock(obj)
    return i

cdef class input(object):
    cdef nmsg_input_t _instance
    cdef object fileobj
    cdef str input_type

    open_file = staticmethod(input_open_file)
    open_sock = staticmethod(input_open_sock)

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_input_close(&self._instance)

    def __repr__(self):
        return 'nmsg input object type=%s _instance=0x%x' % (self.input_type, <uint64_t> self._instance)

    cpdef _open_file(self, fileobj):
        self.fileobj = fileobj
        self._instance = nmsg_input_open_file(fileobj.fileno())
        if self._instance == NULL:
            self.fileobj = None
            raise Exception, 'nmsg_input_open_file() failed'
        self.input_type = 'file'

    cpdef _open_sock(self, fileobj):
        self.fileobj = fileobj
        self._instance = nmsg_input_open_sock(fileobj.fileno())
        if self._instance == NULL:
            self.fileobj = None
            raise Exception, 'nmsg_input_open_file() failed'
        self.input_type = 'socket'

    def close(self):
        nmsg_input_close(&self._instance)
        self._instance = NULL

    def read(self):
        cdef int err
        cdef nmsg_res res
        cdef nmsg_message_t _msg
        cdef _recv_message msg

        if self._instance == NULL:
            raise Exception, 'object not initialized'

        res = nmsg_res_failure

        while res != nmsg_res_success:
            res = nmsg_input_read(self._instance, &_msg)
            if res == nmsg_res_eof:
                return None
            elif res == nmsg_res_again:
                err = PyErr_CheckSignals()
                if err != 0:
                    if PyErr_ExceptionMatches(KeyboardInterrupt):
                        raise KeyboardInterrupt
                else:
                    return None
        
        msg = _recv_message()
        msg.set_instance(_msg)
        return msg

    def set_filter_msgtype(self, vid, msgtype):
        if self._instance == NULL:
            raise Exception, 'object not initialized'
        if type(vid) == str:
            vid = msgmod_vname_to_vid(vid)
        if type(msgtype) == str:
            msgtype = msgmod_mname_to_msgtype(vid, msgtype)
        nmsg_input_set_filter_msgtype(self._instance, vid, msgtype)

    def set_filter_source(self, unsigned source):
        if self._instance == NULL:
            raise Exception, 'object not initialized'
        nmsg_input_set_filter_source(self._instance, source)

    def set_filter_operator(self, str s_operator):
        cdef unsigned operator

        if self._instance == NULL:
            raise Exception, 'object not initialized'
        operator = nmsg_alias_by_value(nmsg_alias_operator, PyString_AsString(s_operator))
        if operator == 0:
            raise Exception, 'unknown operator %s' % s_operator
        nmsg_input_set_filter_operator(self._instance, operator)

    def set_filter_group(self, str s_group):
        cdef unsigned group

        if self._instance == NULL:
            raise Exception, 'object not initialized'
        group = nmsg_alias_by_value(nmsg_alias_group, PyString_AsString(s_group))
        if group == 0:
            raise Exception, 'unknown group %s' % s_group
        nmsg_input_set_filter_group(self._instance, group)

    def set_blocking_io(self, bool flag):
        cdef nmsg_res res

        res = nmsg_input_set_blocking_io(self._instance, flag)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_input_set_blocking_io() failed'
