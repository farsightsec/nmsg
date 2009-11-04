def input_open_file(fileobj):
    if type(fileobj) == str:
        fileobj = open(fileobj)
    i = input()
    i._open_file(fileobj.fileno())
    i.fileobj = fileobj
    return i

def input_open_sock(fileobj):
    i = input()
    i._open_sock(fileobj.fileno())
    i.fileobj = fileobj
    return i

cdef class input(object):
    cdef nmsg_input_t _instance
    cdef public object fileobj

    open_file = staticmethod(input_open_file)
    open_sock = staticmethod(input_open_sock)

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_input_close(&self._instance)

    cpdef _open_file(self, int fileno):
        self._instance = nmsg_input_open_file(fileno)
        if self._instance == NULL:
            raise Exception, 'nmsg_input_open_file() failed'

    cpdef _open_sock(self, int fileno):
        self._instance = nmsg_input_open_sock(fileno)
        if self._instance == NULL:
            raise Exception, 'nmsg_input_open_file() failed'

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
