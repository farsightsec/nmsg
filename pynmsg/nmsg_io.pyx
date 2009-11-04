cdef void callback(nmsg_message_t _msg, void *user) with gil:
    cdef _recv_message msg

    msg = _recv_message()
    msg.set_instance(_msg)

    try:
        (<object>user)(msg)
    finally:
        msg._instance = NULL

cdef class io(object):
    cdef nmsg_io_t _instance

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_io_destroy(&self._instance)

    def __init__(self):
        self._instance = nmsg_io_init()
        if self._instance == NULL:
            raise Exception, 'nmsg_io_init() failed'
        #nmsg_io_set_debug(self._instance, 4)

    def add_input(self, input i):
        cdef nmsg_res res

        res = nmsg_io_add_input(self._instance, i._instance, NULL)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_add_input() failed'
        i._instance = NULL

    def add_output(self, output o):
        cdef nmsg_res

        res = nmsg_io_add_output(self._instance, o._instance, NULL)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_add_output() failed'
        o._instance = NULL

    def add_output_callback(self, fn):
        cdef nmsg_output_t o
        cdef nmsg_res res

        o = nmsg_output_open_callback(<nmsg_cb_message>callback, <void*>fn)
        if o == NULL:
            raise Exception, 'nmsg_output_open_callback() failed'
        
        res = nmsg_io_add_output(self._instance, o, NULL)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_add_output() failed'

    def loop(self):
        cdef nmsg_res res

        with nogil:
            res = nmsg_io_loop(self._instance)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_loop() failed'
