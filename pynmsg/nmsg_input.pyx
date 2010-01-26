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

    open_file = staticmethod(input_open_file)
    open_sock = staticmethod(input_open_sock)

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_input_close(&self._instance)

    cpdef _open_file(self, fileobj):
        self.fileobj = fileobj
        self._instance = nmsg_input_open_file(fileobj.fileno())
        if self._instance == NULL:
            self.fileobj = None
            raise Exception, 'nmsg_input_open_file() failed'

    cpdef _open_sock(self, fileobj):
        self.fileobj = fileobj
        self._instance = nmsg_input_open_sock(fileobj.fileno())
        if self._instance == NULL:
            self.fileobj = None
            raise Exception, 'nmsg_input_open_file() failed'

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
        
        msg = _recv_message()
        msg.set_instance(_msg)
        return msg
