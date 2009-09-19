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
    #int PyString_AsStringAndSize(object obj, char **buffer, Py_ssize_t* length) except -1
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

    unsigned WDNS_FLAGS_QR(uint16_t flags)
    unsigned WDNS_FLAGS_OPCODE(uint16_t flags)
    unsigned WDNS_FLAGS_AA(uint16_t flags)
    unsigned WDNS_FLAGS_TC(uint16_t flags)
    unsigned WDNS_FLAGS_RD(uint16_t flags)
    unsigned WDNS_FLAGS_RA(uint16_t flags)
    unsigned WDNS_FLAGS_Z(uint16_t flags)
    unsigned WDNS_FLAGS_AD(uint16_t flags)
    unsigned WDNS_FLAGS_CD(uint16_t flags)
    unsigned WDNS_FLAGS_RCODE(uint16_t flags)

    void    wdns_clear_message(wdns_message_t *m)
    void    wdns_clear_query(wdns_query_t *q)
    void    wdns_clear_rr(wdns_rr_t *rr)
    void    wdns_clear_rrset(wdns_rrset_t *rrset)
    void    wdns_clear_rrset(wdns_rrset_array_t *a)

    char *  wdns_name_to_str(wdns_name_t *name)
    char *  wdns_rdata_to_str(wdns_rdata_t *rdata, uint16_t rrtype, uint16_t rrclass)
    size_t  wdns_domain_to_str(uint8_t *src, char *dst)
    size_t  wdns_name_skip(uint8_t **data, uint8_t *eod)
    void    wdns_print_question_record(FILE *fp, wdns_qrr_t *q)
    void    wdns_print_rr(FILE *fp, uint8_t *dname, uint16_t rrtype, uint16_t rrclass, uint32_t rrttl, uint16_t rdlen, uint8_t *rdata)
    void    wdns_print_message(FILE *fp, wdns_message_t *m)
    void    wdns_print_rrset(FILE *fp, wdns_rrset_t *rrset)
    void    wdns_print_rrset_array(FILE *fp, wdns_rrset_array_t *a)

    wdns_msg_status wdns_name_len_uncomp(uint8_t *p, uint8_t *eop, size_t *sz)

    wdns_msg_status wdns_name_unpack(uint8_t *p, uint8_t *eop, uint8_t *src, uint8_t *dst, size_t *sz)

    wdns_msg_status wdns_parse_message(uint8_t *op, uint8_t *eop, wdns_message_t *m)

    wdns_msg_status wdns_parse_message_rr(uint8_t *p, uint8_t *eop, uint8_t *data, size_t *rrsz, wdns_rr_t *rr)

    wdns_msg_status wdns_parse_question_record(uint8_t *q, uint8_t *eoq, wdns_qrr_t *question)

    wdns_msg_status wdns_parse_rdata(uint8_t *p, uint8_t *eop, uint8_t *ordata, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, size_t *alloc_bytes, uint8_t *dst)

    wdns_msg_status wdns_parse_header(uint8_t *p, size_t len, uint16_t *id, uint16_t *flags, uint16_t *qdcount, uint16_t *ancount, uint16_t *nscount, uint16_t *arcount)
