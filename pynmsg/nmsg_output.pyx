def output_open_file(obj, size_t bufsz=NMSG_WBUFSZ_MAX):
    if type(obj) == str:
        obj = open(obj, 'w')
    o = output()
    o._open_file(obj.fileno(), bufsz)
    o.fileobj = obj
    return o

def output_open_sock(addr, port, size_t bufsz=NMSG_WBUFSZ_ETHER):
    obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    obj.connect((addr, port))
    obj.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    o = output()
    o._open_sock(obj.fileno(), bufsz)
    o.fileobj = obj
    return o

def output_open_callback(func):
    o = output()
    o._open_callback(func)
    return o

cdef void callback(nmsg_message_t _msg, void *user) with gil:
    cdef _recv_message msg

    msg = _recv_message()
    msg.set_instance(_msg)

    (<object>user)(msg)

cdef class output(object):
    cdef nmsg_output_t _instance
    cdef public object fileobj
    cdef str output_type

    open_file = staticmethod(output_open_file)
    open_sock = staticmethod(output_open_sock)
    open_callback = staticmethod(output_open_callback)

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_output_close(&self._instance)

    def __repr__(self):
        return 'nmsg output object type=%s _instance=0x%x' % (self.output_type, <uint64_t> self._instance)

    cpdef _open_file(self, int fileno, size_t bufsz):
        self._instance = nmsg_output_open_file(fileno, bufsz)
        if self._instance == NULL:
            raise Exception, 'nmsg_output_open_file() failed'
        self.output_type = 'file'

    cpdef _open_sock(self, int fileno, size_t bufsz):
        self._instance = nmsg_output_open_sock(fileno, bufsz)
        if self._instance == NULL:
            raise Exception, 'nmsg_output_open_sock() failed'
        self.output_type = 'socket'

    cpdef _open_callback(self, object func):
        self._instance = nmsg_output_open_callback(<nmsg_cb_message>callback, <void*>func)
        if self._instance == NULL:
            raise Exception, 'nmsg_output_open_callback() failed'
        self.output_type = 'callback'

    def set_filter_msgtype(self, vid, msgtype):
        if self._instance == NULL:
            raise Exception, 'object not initialized'
        if type(vid) == str:
            vid = msgmod_vname_to_vid(vid)
        if type(msgtype) == str:
            msgtype = msgmod_mname_to_msgtype(vid, msgtype)
        nmsg_output_set_filter_msgtype(self._instance, vid, msgtype)

    def close(self):
        nmsg_output_close(&self._instance)
        self._instance = NULL

    def set_buffered(self, bool buffered):
        if self._instance != NULL:
            nmsg_output_set_buffered(self._instance, buffered)

    def set_zlibout(self, bool zlibout):
        if self._instance != NULL:
            nmsg_output_set_zlibout(self._instance, zlibout)

    def write(self, message msg):
        cdef nmsg_res res
        cdef nmsg_message_t _msg_instance

        if self._instance == NULL:
            raise Exception, 'object not initialized'

        if not msg:
            return

        if msg._instance == NULL:
            msg.reinit()

        if msg.changed:
            msg.sync_message()

        msg.sync_fields()

        _msg_instance = msg._instance
        msg._instance = NULL

        res = nmsg_output_write(self._instance, _msg_instance)
        if res != nmsg_res_success:
            nmsg_message_destroy(&_msg_instance)
            raise Exception, 'nmsg_output_write() failed'
        nmsg_message_destroy(&_msg_instance)
