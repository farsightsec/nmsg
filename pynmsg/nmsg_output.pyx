def output_open_file(obj, size_t bufsz=NMSG_WBUFSZ_MAX):
    if type(obj) == str:
        obj = open(obj, 'w')
    o = output()
    o._open_file(obj.fileno(), bufsz)
    o.fileobj = obj
    return o

def output_open_sock(addr, port, size_t bufsz=NMSG_WBUFSZ_ETHER):
    obj = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    obj.setsockopt(socket.SO_REUSEADDR, 1)
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

    try:
        (<object>user)(msg)
    finally:
        msg._instance = NULL

cdef class output(object):
    cdef nmsg_output_t _instance
    cdef public object fileobj

    open_file = staticmethod(output_open_file)
    open_sock = staticmethod(output_open_sock)
    open_callback = staticmethod(output_open_callback)

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_output_close(&self._instance)

    cpdef _open_file(self, int fileno, size_t bufsz):
        self._instance = nmsg_output_open_file(fileno, bufsz)
        if self._instance == NULL:
            raise Exception, 'nmsg_output_open_file() failed'

    cpdef _open_sock(self, int fileno, size_t bufsz):
        self._instance = nmsg_output_open_sock(fileno, bufsz)
        if self._instance == NULL:
            raise Exception, 'nmsg_output_open_sock() failed'

    cpdef _open_callback(self, object func):
        self._instance = nmsg_output_open_callback(<nmsg_cb_message>callback, <void*>func)
        if self._instance == NULL:
            raise Exception, 'nmsg_output_open_callback() failed'
