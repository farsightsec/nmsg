cdef class io(object):
    cdef nmsg_io_t _instance

    cdef int filter_vid
    cdef int filter_msgtype
    cdef list inputs
    cdef list outputs

    def __cinit__(self):
        self._instance = NULL

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_io_destroy(&self._instance)

    def __init__(self):
        self.filter_vid = 0
        self.filter_msgtype = 0
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

        found_channel = False
        for line in open(fname):
            ch, socks = line.strip().split(None, 1)
            if ch == ch_input:
                found_channel = True
                for sock in socks.split():
                    addr, portspec = sock.split('/', 1)
                    if '..' in portspec:
                        portrange = [ int(p) for p in portspec.split('..', 1) ]
                        for port in range(portrange[0], portrange[1] + 1):
                            i = input.open_sock(addr, port)
                            self.add_input(i)
                    else:
                        i = input.open_sock(addr, portspec)
                        self.add_input(i)
        if not found_channel:
            raise Exception, 'lookup of channel %s failed'

    def add_output(self, output o):
        cdef nmsg_res

        res = nmsg_io_add_output(self._instance, o._instance, NULL)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_add_output() failed'
        self.outputs.append(o)
        o._instance = NULL

    def set_filter_msgtype(self, vid, msgtype):
        if type(vid) == str:
            vid = msgmod_vname_to_vid(vid)
        if type(msgtype) == str:
            msgtype = msgmod_mname_to_msgtype(vid, msgtype)

        self.filter_vid = vid
        self.filter_msgtype = msgtype

    def loop(self):
        cdef nmsg_res res

        if self.filter_vid != 0 and self.filter_msgtype != 0:
            for o in self.outputs:
                o.set_filter_msgtype(self.filter_vid, self.filter_msgtype)

        with nogil:
            res = nmsg_io_loop(self._instance)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_loop() failed: %s' % (nmsg_res_lookup(res))
