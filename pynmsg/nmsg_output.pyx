def output_open_file(fileobj, size_t bufsz=NMSG_WBUFSZ_MAX):
    if type(fileobj) == str:
        fileobj = open(fileobj, 'w')
    o = output()
    o._open_file(fileobj.fileno(), bufsz)
    o.fileobj = fileobj
    return o

def output_open_sock(fileobj, size_t bufsz=NMSG_WBUFSZ_ETHER):
    o = output()
    o._open_sock(fileobj.fileno(), bufsz)
    o.fileobj = fileobj
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
