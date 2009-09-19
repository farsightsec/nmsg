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

cdef extern from "wreck.h":

    ctypedef enum wreck_msg_status:
        wreck_msg_success
        wreck_msg_err_invalid_compression_pointer
        wreck_msg_err_invalid_length_octet
        wreck_msg_err_invalid_opcode
        wreck_msg_err_invalid_rcode
        wreck_msg_err_len
        wreck_msg_err_malloc
        wreck_msg_err_name_len
        wreck_msg_err_name_overflow
        wreck_msg_err_out_of_bounds
        wreck_msg_err_overflow
        wreck_msg_err_parse_error
        wreck_msg_err_qdcount
        wreck_msg_err_unknown_opcode
        wreck_msg_err_unknown_rcode

    ctypedef struct wreck_dns_name_t:
        uint16_t            len
        uint8_t             *data

    ctypedef struct wreck_dns_rdata_t:
        uint16_t            len
        uint8_t             data[0]

    ctypedef struct wreck_dns_qrr_t:
        uint16_t            rrtype
        uint16_t            rrclass
        wreck_dns_name_t    name

    ctypedef struct wreck_dns_query_t:
        uint16_t            id
        uint16_t            flags
        wreck_dns_qrr_t     question

    ctypedef struct wreck_dns_rr_t:
        uint32_t            rrttl
        uint16_t            rrtype
        uint16_t            rrclass
        wreck_dns_name_t    name
        wreck_dns_rdata_t   *rdata

    ctypedef struct wreck_dns_rrset_t:
        uint32_t            rrttl
        uint16_t            rrtype
        uint16_t            rrclass
        uint16_t            n_rdatas
        wreck_dns_name_t    name
        wreck_dns_rdata_t   **rdatas

    ctypedef struct wreck_dns_rrset_array_t:
        uint16_t            n_rrsets
        wreck_dns_rrset_t   **rrsets

    ctypedef struct wreck_dns_message_t:
        uint16_t            id
        uint16_t            flags
        wreck_dns_qrr_t     question
        wreck_dns_rrset_array_t sections[3]

    unsigned WRECK_DNS_FLAGS_QR(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_OPCODE(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_AA(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_TC(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_RD(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_RA(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_Z(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_AD(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_CD(uint16_t flags)
    unsigned WRECK_DNS_FLAGS_RCODE(uint16_t flags)

    void    wreck_dns_message_clear(wreck_dns_message_t *m)
    void    wreck_dns_query_clear(wreck_dns_query_t *q)
    void    wreck_dns_rr_clear(wreck_dns_rr_t *rr)
    void    wreck_dns_rrset_clear(wreck_dns_rrset_t *rrset)
    void    wreck_dns_rrset_array_clear(wreck_dns_rrset_array_t *a)

    char *  wreck_name_to_str(wreck_dns_name_t *name)
    char *  wreck_rdata_to_str(wreck_dns_rdata_t *rdata, uint16_t rrtype, uint16_t rrclass)
    size_t  wreck_domain_to_str(uint8_t *src, char *dst)
    size_t  wreck_name_skip(uint8_t **data, uint8_t *eod)
    void    wreck_print_question_record(FILE *fp, wreck_dns_qrr_t *q)
    void    wreck_print_rr(FILE *fp, uint8_t *dname, uint16_t rrtype, uint16_t rrclass, uint32_t rrttl, uint16_t rdlen, uint8_t *rdata)
    void    wreck_print_data(uint8_t *p, size_t len)
    void    wreck_print_message(FILE *fp, wreck_dns_message_t *m)
    void    wreck_print_rrset(FILE *fp, wreck_dns_rrset_t *rrset)
    void    wreck_print_rrset_array(FILE *fp, wreck_dns_rrset_array_t *a)

    wreck_msg_status wreck_name_len_uncomp(uint8_t *p, uint8_t *eop, size_t *sz)

    wreck_msg_status wreck_name_unpack(uint8_t *p, uint8_t *eop, uint8_t *src, uint8_t *dst, size_t *sz)

    wreck_msg_status wreck_parse_message(uint8_t *op, uint8_t *eop, wreck_dns_message_t *m)

    wreck_msg_status wreck_parse_message_rr(uint8_t *p, uint8_t *eop, uint8_t *data, size_t *rrsz, wreck_dns_rr_t *rr)

    wreck_msg_status wreck_parse_question_record(uint8_t *q, uint8_t *eoq, wreck_dns_qrr_t *question)

    wreck_msg_status wreck_parse_rdata(uint8_t *p, uint8_t *eop, uint8_t *ordata, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, size_t *alloc_bytes, uint8_t *dst)

    wreck_msg_status wreck_parse_header(uint8_t *p, size_t len, uint16_t *id, uint16_t *flags, uint16_t *qdcount, uint16_t *ancount, uint16_t *nscount, uint16_t *arcount)
