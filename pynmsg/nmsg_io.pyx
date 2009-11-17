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
    cdef list inputs
    cdef list outputs

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_io_destroy(&self._instance)

    def __init__(self):
        self.inputs = []
        self.outputs = []

        self._instance = nmsg_io_init()
        if self._instance == NULL:
            raise Exception, 'nmsg_io_init() failed'
        #nmsg_io_set_debug(self._instance, 4)

    def add_input(self, input i):
        cdef nmsg_res res

        res = nmsg_io_add_input(self._instance, i._instance, NULL)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_add_input() failed'
        self.inputs.append(i)
        i._instance = NULL

    def add_input_channel(self, str ch_input):
        fname = None
        for f in chalias_fnames:
            if os.path.isfile(f):
                fname = f
        if fname == None:
            raise Exception, 'unable to locate nmsg channel alias file'

        for line in open(fname):
            ch, socks = line.strip().split(None, 1)
            if ch == ch_input:
                for sock in socks.split():
                    addr, ports = sock.split('/', 1)
                    portrange = [ int(p) for p in ports.split('..', 1) ]
                    for port in range(portrange[0], portrange[1] + 1):
                        i = input.open_sock(addr, port)
                        self.add_input(i)

    def add_output(self, output o):
        cdef nmsg_res

        res = nmsg_io_add_output(self._instance, o._instance, NULL)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_add_output() failed'
        self.outputs.append(o)
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
            raise Exception, 'nmsg_io_loop() failed: %s' % (nmsg_res_lookup(res))
