cdef class io(object):
    cdef nmsg_io_t _instance

    cdef unsigned filter_vid
    cdef unsigned filter_msgtype

    cdef unsigned filter_source
    cdef str filter_operator
    cdef str filter_group

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
        self.filter_source = 0
        self.inputs = []
        self.outputs = []

        self._instance = nmsg_io_init()
        if self._instance == NULL:
            raise Exception, 'nmsg_io_init() failed'
        #nmsg_io_set_debug(self._instance, 4)

    def add_input(self, input i):
        cdef nmsg_res res

        if i._instance == NULL:
            raise Exception, 'input object not initialized'

        i.set_filter_msgtype(self.filter_vid, self.filter_msgtype)
        i.set_filter_source(self.filter_source)
        if self.filter_operator:
            i.set_filter_operator(self.filter_operator)
        if self.filter_group:
            i.set_filter_group(self.filter_group)

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

        if o._instance == NULL:
            raise Exception, 'output object not initialized'

        o.set_filter_msgtype(self.filter_vid, self.filter_msgtype)

        res = nmsg_io_add_output(self._instance, o._instance, NULL)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_add_output() failed'
        self.outputs.append(o)
        o._instance = NULL

    def add_output_callback(self, fn):
        cdef output o
        cdef nmsg_res res

        o = output.open_callback(fn)
        self.add_output(o)

    def set_filter_msgtype(self, vid, msgtype):
        if type(vid) == str:
            vid = msgmod_vname_to_vid(vid)
        if type(msgtype) == str:
            msgtype = msgmod_mname_to_msgtype(vid, msgtype)

        self.filter_vid = vid
        self.filter_msgtype = msgtype

    def set_filter_source(self, unsigned source):
        self.filter_source = source

    def set_filter_operator(self, str s_operator):
        operator = nmsg_alias_by_value(nmsg_alias_operator, PyString_AsString(s_operator))
        if operator == 0:
            raise Exception, 'unknown operator %s' % s_operator
        self.filter_operator = s_operator

    def set_filter_group(self, str s_group):
        group = nmsg_alias_by_value(nmsg_alias_group, PyString_AsString(s_group))
        if group == 0:
            raise Exception, 'unknown group %s' % s_group
        self.filter_group = s_group

    def loop(self):
        cdef nmsg_res res

        with nogil:
            res = nmsg_io_loop(self._instance)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_io_loop() failed: %s' % (nmsg_res_lookup(res))
