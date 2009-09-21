cdef extern from "stdio.h":
    ctypedef void FILE
    FILE *stdout

cdef extern from "stdint.h":
    ctypedef unsigned char uint8_t
    ctypedef unsigned short uint16_t
    ctypedef unsigned int uint32_t

cdef extern from "stdlib.h":
    ctypedef unsigned long size_t
    void free(void *ptr)
    void *malloc(size_t size)
    void *realloc(void *ptr, size_t size)
    size_t strlen(char *s)
    char *strcpy(char *dest, char *src)
 
cdef extern from "Python.h":
    object PyString_FromStringAndSize(char *v, int len)
    Py_ssize_t PyString_Size(object string)
    char *PyString_AsString(object string)

cdef extern from "msg/msg.h":

    ctypedef enum wdns_msg_status:
        wdns_msg_success
        wdns_msg_err_invalid_compression_pointer
        wdns_msg_err_invalid_length_octet
        wdns_msg_err_invalid_opcode
        wdns_msg_err_invalid_rcode
        wdns_msg_err_len
        wdns_msg_err_malloc
        wdns_msg_err_name_len
        wdns_msg_err_name_overflow
        wdns_msg_err_out_of_bounds
        wdns_msg_err_overflow
        wdns_msg_err_parse_error
        wdns_msg_err_qdcount
        wdns_msg_err_unknown_opcode
        wdns_msg_err_unknown_rcode

    ctypedef struct wdns_name_t:
        uint16_t            len
        uint8_t             *data

    ctypedef struct wdns_rdata_t:
        uint16_t            len
        uint8_t             data[0]

    ctypedef struct wdns_qrr_t:
        uint16_t            rrtype
        uint16_t            rrclass
        wdns_name_t         name

    ctypedef struct wdns_query_t:
        uint16_t            id
        uint16_t            flags
        wdns_qrr_t          question

    ctypedef struct wdns_rr_t:
        uint32_t            rrttl
        uint16_t            rrtype
        uint16_t            rrclass
        wdns_name_t         name
        wdns_rdata_t        *rdata

    ctypedef struct wdns_rrset_t:
        uint32_t            rrttl
        uint16_t            rrtype
        uint16_t            rrclass
        uint16_t            n_rdatas
        wdns_name_t         name
        wdns_rdata_t        **rdatas

    ctypedef struct wdns_rrset_array_t:
        uint16_t            n_rrsets
        wdns_rrset_t        **rrsets

    ctypedef struct wdns_message_t:
        uint16_t            id
        uint16_t            flags
        wdns_qrr_t          question
        wdns_rrset_array_t  sections[3]

    void    wdns_clear_message(wdns_message_t *m)

    size_t  wdns_domain_to_str(uint8_t *src, char *dst)

    wdns_msg_status wdns_parse_message(uint8_t *op, uint8_t *eop, wdns_message_t *m)
