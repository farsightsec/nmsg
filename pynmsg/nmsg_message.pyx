cdef class message(object):
    cdef msgmod _mod
    cdef nmsg_message_t _instance
    cdef bool changed
    cdef public int vid
    cdef public int msgtype
    cdef public long time_sec
    cdef public int time_nsec
    cdef public long source
    cdef public str operator
    cdef public str group
    cdef readonly bool has_source
    cdef readonly bool has_operator
    cdef readonly bool has_group

    cdef readonly object fields
    cdef readonly object field_types
    cdef readonly object field_names

    def __cinit__(self):
        self._instance = NULL
        self._mod = None
        self.vid = 0
        self.msgtype = 0
        self.has_source = False
        self.has_operator = False
        self.has_group = False
        self.changed = False

    def __init__(self, unsigned vid, unsigned msgtype):
        self.vid = vid
        self.msgtype = msgtype
        self._mod = msgmod(self.vid, self.msgtype)
        self._instance = nmsg_message_init(self._mod._instance)
        if self._instance == NULL:
            raise Exception, 'nmsg_message_init() failed'

        self.load_fields()

    def __dealloc__(self):
        if self._instance != NULL:
            nmsg_message_destroy(&self._instance)

    cdef reinit(self):
        if self._mod == None:
            self._mod = msgmod(self.vid, self.msgtype)
        if self._instance == NULL:
            self._instance = nmsg_message_init(self._mod._instance)
            if self._instance == NULL:
                raise Exception, 'nmsg_message_init() failed'
            self.changed = True

    cdef set_instance(self, nmsg_message_t instance):
        cdef timespec ts
        cdef uint32_t *u

        if self._instance != NULL:
            nmsg_message_destroy(&self._instance)
        self._instance = instance

        self.vid = nmsg_message_get_vid(instance)
        self.msgtype = nmsg_message_get_msgtype(instance)

        nmsg_message_get_time(instance, &ts)
        self.time_sec = ts.tv_sec
        self.time_nsec = ts.tv_nsec

        u = nmsg_message_get_source(instance)
        if u != NULL:
            self.has_source = True
            self.source = u[0]

        u = nmsg_message_get_operator(instance)
        if u != NULL:
            self.has_operator = True
            self.operator = nmsg_alias_by_key(nmsg_alias_operator, u[0])
        else:
            self.operator = None

        u = nmsg_message_get_group(instance)
        if u != NULL:
            self.has_group = True
            self.group = nmsg_alias_by_key(nmsg_alias_group, u[0])
        else:
            self.group = None

        self.load_fields()

    cdef load_fields(self):
        cdef nmsg_res res
        cdef size_t n_fields
        cdef size_t n_field_values
        cdef char *field_name
        cdef nmsg_msgmod_field_type field_type
        cdef unsigned field_flags

        cdef unsigned val_enum
        cdef uint32_t val_uint32
        cdef uint64_t val_uint64
        cdef int32_t val_int32
        cdef int64_t val_int64
        cdef uint8_t *data
        cdef size_t data_len

        self.fields = {}
        self.field_types = {}
        self.field_names = set()

        res = nmsg_message_get_num_fields(self._instance, &n_fields)
        if res != nmsg_res_success:
            raise Exception, 'nmsg_message_get_num_fields() failed'

        for field_idx from 0 <= field_idx < n_fields:
            res = nmsg_message_get_field_name(self._instance, field_idx, &field_name)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_field_name() failed'

            self.field_names.add(field_name)

            res = nmsg_message_get_field_type_by_idx(self._instance, field_idx, &field_type)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_field_type_by_idx() failed'

            res = nmsg_message_get_num_field_values_by_idx(self._instance, field_idx, &n_field_values)

            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_num_field_values_by_idx() failed'

            val_list = []

            for val_idx from 0 <= val_idx < n_field_values:
                res = nmsg_message_get_field_ptr_by_idx(self._instance, field_idx, val_idx, &data, &data_len)
                if res != nmsg_res_success:
                    raise Exception, 'nmsg_message_get_field_ptr_by_idx() failed'

                if field_type == nmsg_msgmod_ft_enum:
                    val_enum = (<unsigned *> data)[0]
                    val_list.append(val_enum)

                elif field_type == nmsg_msgmod_ft_bytes:
                    s = PyString_FromStringAndSize(<char *> data, data_len)
                    val_list.append(s)

                elif field_type == nmsg_msgmod_ft_string or \
                        field_type == nmsg_msgmod_ft_mlstring:
                    if data_len > 0 and data[data_len - 1] == '\x00':
                        data_len -= 1
                    s = PyString_FromStringAndSize(<char *> data, data_len)
                    val_list.append(s)

                elif field_type == nmsg_msgmod_ft_ip:
                    ip = PyString_FromStringAndSize(<char *> data, data_len)
                    if data_len == 4:
                        sip = socket.inet_ntop(socket.AF_INET, ip)
                    elif data_len == 16:
                        sip = socket.inet_ntop(socket.AF_INET6, ip)
                    val_list.append(sip)

                elif field_type == nmsg_msgmod_ft_uint16 or \
                        field_type == nmsg_msgmod_ft_uint32:
                    val_uint32 = (<uint32_t *> data)[0]
                    val_list.append(val_uint32)

                elif field_type == nmsg_msgmod_ft_uint64:
                    val_uint64 = (<uint64_t *> data)[0]
                    val_list.append(val_uint64)

                elif field_type == nmsg_msgmod_ft_int16 or \
                        field_type == nmsg_msgmod_ft_int32:
                    val_int32 = (<int32_t *> data)[0]
                    val_list.append(val_int32)

                elif field_type == nmsg_msgmod_ft_int64:
                    val_int64 = (<int64_t *> data)[0]
                    val_list.append(val_int64)

            res = nmsg_message_get_field_flags_by_idx(self._instance, field_idx, &field_flags)
            if res != nmsg_res_success:
                raise Exception, 'nmsg_message_get_field_flags_by_idx() failed'
            if len(val_list) > 0:
                if field_flags & NMSG_MSGMOD_FIELD_REPEATED:
                    self.fields[field_name] = val_list
                else:
                    self.fields[field_name] = val_list[0]
            self.field_types[field_name] = field_type

    cdef sync_fields(self):
        cdef nmsg_res res

        cdef nmsg_msgmod_field_type field_type

        cdef unsigned val_enum
        cdef uint16_t val_uint16
        cdef uint32_t val_uint32
        cdef uint64_t val_uint64
        cdef int16_t val_int16
        cdef int32_t val_int32
        cdef int64_t val_int64
        cdef char *val_buf
        cdef Py_ssize_t val_buf_len
        cdef uint8_t *data
        cdef size_t data_len

        if self._instance == NULL:
            self.reinit()

        for field_name in self.fields:
            field_type = self.field_types[field_name]

            if type(self.fields[field_name]) == list:
                fields = self.fields[field_name]
            else:
                fields = [ self.fields[field_name] ]

            for i in range(0, len(fields)):
                if field_type == nmsg_msgmod_ft_enum:
                    val_enum = fields[i]
                    data = <uint8_t *> &val_enum
                    data_len = sizeof(val_enum)

                elif field_type == nmsg_msgmod_ft_bytes or \
                        field_type == nmsg_msgmod_ft_string or \
                        field_type == nmsg_msgmod_ft_mlstring:
                    PyString_AsStringAndSize(fields[i], &val_buf, &val_buf_len)
                    data = <uint8_t *> val_buf
                    data_len = val_buf_len

                elif field_type == nmsg_msgmod_ft_ip:
                    try:
                        ip = socket.inet_pton(socket.AF_INET, fields[i])
                    except:
                        ip = socket.inet_pton(socket.AF_INET6, fields[i])
                    PyString_AsStringAndSize(ip, &val_buf, &val_buf_len)
                    data = <uint8_t *> val_buf
                    data_len = val_buf_len

                elif field_type == nmsg_msgmod_ft_uint16:
                    val_uint16 = fields[i]
                    data = <uint8_t *> &val_uint16
                    data_len = sizeof(val_uint16)

                elif field_type == nmsg_msgmod_ft_int16:
                    val_int16 = fields[i]
                    data = <uint8_t *> &val_int16
                    data_len = sizeof(val_int16)

                elif field_type == nmsg_msgmod_ft_uint32:
                    val_uint32 = fields[i]
                    data = <uint8_t *> &val_uint32
                    data_len = sizeof(val_uint32)

                elif field_type == nmsg_msgmod_ft_int32:
                    val_int32 = fields[i]
                    data = <uint8_t *> &val_int32
                    data_len = sizeof(val_int32)

                elif field_type == nmsg_msgmod_ft_uint64:
                    val_uint64 = fields[i]
                    data = <uint8_t *> &val_uint64
                    data_len = sizeof(val_uint64)

                elif field_type == nmsg_msgmod_ft_int64:
                    val_int64 = fields[i]
                    data = <uint8_t *> &val_int64
                    data_len = sizeof(val_int64)

                else:
                    raise Exception, 'unknown field_type'

                res = nmsg_message_set_field(self._instance, field_name, i, data, data_len)
                if res != nmsg_res_success:
                    raise Exception, 'nmsg_message_set_field() failed'

        self.changed = False

    def __getitem__(self, key):
        return self.fields[key]

    def __setitem__(self, key, value):
        if key in self.field_names:
            self.fields[key] = value
            self.changed = True
        else:
            raise KeyError(key)

    def __repr__(self):
        return repr(self.fields)

    def keys(self):
        return self.fields.keys()

    def clear(self):
        self.fields = {}
        if self._instance != NULL:
            nmsg_message_clear(self._instance)

cdef class _recv_message(message):
    def __init__(self):
        pass

cdef class _meta_message(message):
    def __init__(self):
        message.__init__(self, self.__vid, self.__msgtype)
