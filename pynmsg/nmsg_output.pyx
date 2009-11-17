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

cdef class output(object):
    cdef nmsg_output_t _instance
    cdef public object fileobj

    open_file = staticmethod(output_open_file)
    open_sock = staticmethod(output_open_sock)

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
