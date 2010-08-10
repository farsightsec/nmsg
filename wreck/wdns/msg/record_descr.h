#ifndef WDNS_RECORD_DESCR_H
#define WDNS_RECORD_DESCR_H

#include <stdint.h>

typedef enum {
	class_un,	/* not class specific */
	class_in	/* Internet class */
} record_class;

typedef enum {
	rdf_unknown,	/* marker for unpopulated entries */
	rdf_bytes,	/* byte array (terminal) */
	rdf_bytes_b64,	/* byte array (terminal) (base64 encoded presentation) */
	rdf_name,	/* series of labels terminated by zero-length label, possibly compressed */
	rdf_uname,	/* series of labels terminated by zero-length label, NOT compressed */
	rdf_int8,	/* 8 bit integer */
	rdf_int16,	/* 16 bit integer */
	rdf_int32,	/* 32 bit integer */
	rdf_ipv4,	/* IPv4 host address */
	rdf_ipv6,	/* IPv6 host address */
	rdf_ipv6prefix,	/* IPv6 prefix: length octet followed by 0-16 octets */
	rdf_string,	/* length octet followed by that many octets */
	rdf_repstring,	/* one or more strings (terminal) */
	rdf_rrtype,	/* resource record type */
	rdf_type_bitmap,/* rr type bitmap */
	rdf_salt,	/* length-prefixed salt value (hex presentation) */
	rdf_hash,	/* length-prefixed hash value (base32 presentation) */
	rdf_end		/* sentinel (terminal) */
} rdf_type;

typedef struct {
	uint16_t	record_class;
	uint8_t		types[10];
} record_descr;

extern const record_descr	record_descr_array[];
extern const size_t		record_descr_len;

#endif /* WDNS_RECORD_DESCR_H */
