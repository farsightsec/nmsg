cdef extern from "stdio.h":
    ctypedef void FILE
    FILE *stdout

cdef extern from "stdbool.h":
    ctypedef int bool

cdef extern from "stdint.h":
    ctypedef unsigned char uint8_t
    ctypedef unsigned short uint16_t
    ctypedef unsigned int uint32_t
    ctypedef unsigned long long uint64_t
    ctypedef signed char int8_t
    ctypedef signed short int16_t
    ctypedef signed int int32_t
    ctypedef signed long long int64_t

cdef extern from "stdlib.h":
    ctypedef unsigned long size_t
    void free(void *ptr)
    void *malloc(size_t size)
    void *realloc(void *ptr, size_t size)
    size_t strlen(char *s)
    char *strcpy(char *dest, char *src)

cdef extern from "time.h":
    struct timespec:
        long tv_sec
        long tv_nsec
 
cdef extern from "Python.h":
    object PyString_FromStringAndSize(char *v, int len)
    Py_ssize_t PyString_Size(object string)
    char *PyString_AsString(object string)
    void Py_INCREF(object)
    void Py_DECREF(object)
    void PyEval_InitThreads()
    int PyErr_CheckSignals()
    int PyErr_ExceptionMatches(object)

cdef extern from "nmsg/msgmod_plugin.h":
    cdef enum:
        NMSG_MSGMOD_FIELD_REPEATED = 0x01
        NMSG_MSGMOD_FIELD_REQUIRED = 0x02

cdef extern from "nmsg.h":
    cdef enum:
        NMSG_WBUFSZ_MIN = 512
        NMSG_WBUFSZ_MAX = 1048576
        NMSG_WBUFSZ_JUMBO = 8192
        NMSG_WBUFSZ_ETHER = 1280

    cdef enum:
        nmsg_alias_operator
        nmsg_alias_group

    ctypedef struct ProtobufCBinaryData:
        size_t len
        uint8_t *data

    ctypedef enum nmsg_res:
        nmsg_res_success
        nmsg_res_failure
        nmsg_res_eof
        nmsg_res_memfail
        nmsg_res_magic_mismatch
        nmsg_res_version_mismatch
        nmsg_res_pbuf_ready
        nmsg_res_nmsg_written
        nmsg_res_notimpl
        nmsg_res_stop
        nmsg_res_again
        nmsg_res_parse_error
        nmsg_res_pcap_error
        nmsg_res_read_failrue

    ctypedef enum nmsg_msgmod_field_type:
        nmsg_msgmod_ft_enum
        nmsg_msgmod_ft_bytes
        nmsg_msgmod_ft_string
        nmsg_msgmod_ft_mlstring
        nmsg_msgmod_ft_ip
        nmsg_msgmod_ft_uint16
        nmsg_msgmod_ft_uint32
        nmsg_msgmod_ft_uint64
        nmsg_msgmod_ft_int16
        nmsg_msgmod_ft_int32
        nmsg_msgmod_ft_int64

    ctypedef enum nmsg_output_type:
        nmsg_output_type_stream
        nmsg_output_type_pres
        nmsg_output_type_callback

    struct nmsg_input:
        pass

    struct nmsg_io:
        pass

    struct nmsg_message:
        pass

    struct nmsg_msgmod:
        pass

    struct nmsg_msgmodset:
        pass

    struct nmsg_output:
        pass

    struct nmsg_pcap:
        pass

    struct nmsg_pres:
        pass

    struct nmsg_rate:
        pass

    struct nmsg_ipreasm:
        pass

    struct nmsg_strbuf:
        pass

    struct nmsg_zbuf:
        pass

    struct nmsg_ipdg:
        int             proto_network
        int             proto_transport
        unsigned        len_network
        unsigned        len_transport
        unsigned        len_payload
        unsigned char   *network
        unsigned char   *transport
        unsigned char   *payload

    ctypedef nmsg_input * nmsg_input_t
    ctypedef nmsg_io * nmsg_io_t
    ctypedef nmsg_message * nmsg_message_t
    ctypedef nmsg_msgmod * nmsg_msgmod_t
    ctypedef nmsg_msgmodset * nmsg_msgmodset_t
    ctypedef nmsg_output * nmsg_output_t
    ctypedef nmsg_pcap * nmsg_pcap_t
    ctypedef nmsg_pres * nmsg_pres_t
    ctypedef nmsg_rate * nmsg_rate_t
    ctypedef nmsg_ipreasm * nmsg_ipreasm_t
    ctypedef nmsg_strbuf * nmsg_strbuf_t
    ctypedef nmsg_zbuf * nmsg_zbuf_t

    ctypedef void (*nmsg_cb_message)(nmsg_message_t, void *user)

    void                nmsg_init()
    void                nmsg_set_autoclose(bool)
    void                nmsg_set_debug(int)

    char *              nmsg_res_lookup(unsigned res)

    char *              nmsg_alias_by_key(unsigned ae, unsigned key)

    nmsg_io_t           nmsg_io_init()
    nmsg_res            nmsg_io_add_input(nmsg_io_t, nmsg_input_t, void *user)
    nmsg_res            nmsg_io_add_output(nmsg_io_t, nmsg_output_t, void *user)
    nmsg_res            nmsg_io_loop(nmsg_io_t) nogil
    void                nmsg_io_breakloop(nmsg_io_t)
    void                nmsg_io_destroy(nmsg_io_t *)
    void                nmsg_io_set_debug(nmsg_io_t, int debug)

    unsigned            nmsg_msgmod_get_max_vid()
    unsigned            nmsg_msgmod_get_max_msgtype(unsigned vid)
    char *              nmsg_msgmod_vid_to_vname(unsigned vid)
    char *              nmsg_msgmod_msgtype_to_mname(unsigned vid, unsigned msgtype)
    nmsg_msgmod_t       nmsg_msgmod_lookup(unsigned vid, unsigned msgtype)
    nmsg_msgmod_t       nmsg_msgmod_lookup_byname(char *vname, char *mname)
    unsigned            nmsg_msgmod_vname_to_vid(char *vname)
    unsigned            nmsg_msgmod_mname_to_msgtype(unsigned vid, char *mname)

    nmsg_res            nmsg_msgmod_init(nmsg_msgmod_t mod, void **clos)
    nmsg_res            nmsg_msgmod_fini(nmsg_msgmod_t mod, void **clos)

    nmsg_message_t      nmsg_message_init(nmsg_msgmod_t mod)
    void                nmsg_message_destroy(nmsg_message_t *msg)
    void                nmsg_message_clear(nmsg_message_t msg)
    nmsg_res            nmsg_message_get_num_fields(nmsg_message_t msg, size_t *n_fields)
    nmsg_res            nmsg_message_get_num_field_values_by_idx(nmsg_message_t msg, unsigned field_idx, size_t *n_field_values)
    nmsg_res            nmsg_message_get_field_name(nmsg_message_t msg, unsigned idx, char **field_name)
    nmsg_res            nmsg_message_get_field_type_by_idx(nmsg_message_t msg, unsigned field_idx, nmsg_msgmod_field_type *type)
    nmsg_res            nmsg_message_get_field_by_idx(nmsg_message_t msg, unsigned field_idx, unsigned val_idx, uint8_t *data, size_t *len)
    nmsg_res            nmsg_message_get_field_ptr_by_idx(nmsg_message_t msg, unsigned field_idx, unsigned val_idx, uint8_t **data, size_t *len)
    nmsg_res            nmsg_message_get_field_flags_by_idx(nmsg_message_t msg, unsigned field_idx, unsigned *flags)

    int32_t             nmsg_message_get_vid(nmsg_message_t msg)
    int32_t             nmsg_message_get_msgtype(nmsg_message_t msg)
    void                nmsg_message_get_time(nmsg_message_t msg, timespec *ts)
    uint32_t *          nmsg_message_get_source(nmsg_message_t msg)
    uint32_t *          nmsg_message_get_operator(nmsg_message_t msg)
    uint32_t *          nmsg_message_get_group(nmsg_message_t msg)

    nmsg_input_t        nmsg_input_open_file(int fd)
    nmsg_input_t        nmsg_input_open_sock(int fd)
    nmsg_res            nmsg_input_close(nmsg_input_t *input)
    nmsg_res            nmsg_input_read(nmsg_input_t input, nmsg_message_t *msg)

    nmsg_output_t       nmsg_output_open_file(int fd, size_t bufsz)
    nmsg_output_t       nmsg_output_open_sock(int fd, size_t bufsz)
    nmsg_output_t       nmsg_output_open_pres(int fd, nmsg_msgmodset_t ms)
    nmsg_output_t       nmsg_output_open_callback(nmsg_cb_message cb, void *user)
    nmsg_res            nmsg_output_write(nmsg_output_t output, nmsg_message_t msg)
    nmsg_res            nmsg_output_close(nmsg_output_t *output)
    void                nmsg_output_set_buffered(nmsg_output_t output, bool buffered)
    void                nmsg_output_set_filter_msgtype(nmsg_output_t output, unsigned vid, unsigned msgtype)
    void                nmsg_output_set_rate(nmsg_output_t output, nmsg_rate_t rate)
    void                nmsg_output_set_endline(nmsg_output_t output, char *endline)
    void                nmsg_output_set_source(nmsg_output_t output, unsigned source)
    void                nmsg_output_set_operator(nmsg_output_t output, unsigned operator)
    void                nmsg_output_set_group(nmsg_output_t output, unsigned group)
    void                nmsg_output_set_zlibout(nmsg_output_t output, bool zlibout)

    nmsg_res            nmsg_ipdg_parse(nmsg_ipdg *, unsigned etype, size_t, unsigned char *pkt)
