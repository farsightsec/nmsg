#include <stdint.h>

#define WRECK_DNS_FLAGS_QR(flags)	((flags >> 15) & 0x01)
#define WRECK_DNS_FLAGS_OPCODE(flags)	((flags >> 11) & 0x0f)
#define WRECK_DNS_FLAGS_AA(flags)	((flags >> 10) & 0x01)
#define WRECK_DNS_FLAGS_TC(flags)	((flags >> 9) & 0x01)
#define WRECK_DNS_FLAGS_RD(flags)	((flags >> 8) & 0x01)
#define WRECK_DNS_FLAGS_RA(flags)	((flags >> 7) & 0x01)
#define WRECK_DNS_FLAGS_Z(flags)	((flags >> 6) & 0x01)
#define WRECK_DNS_FLAGS_AD(flags)	((flags >> 5) & 0x01)
#define WRECK_DNS_FLAGS_CD(flags)	((flags >> 4) & 0x01)
#define WRECK_DNS_FLAGS_RCODE(flags)	(flags & 0xf)

typedef struct {
	uint16_t		len;
	uint8_t			*data;
} wreck_dns_name_t;

typedef struct {
	uint16_t		len;
	uint8_t			data[];
} wreck_dns_rdata_t;

typedef struct {
	uint16_t		rrtype;
	uint16_t		rrclass;
	wreck_dns_name_t	rrname;
} wreck_dns_qrr_t;

typedef struct {
	uint16_t		id;
	uint16_t		flags;
	wreck_dns_qrr_t		question;
} wreck_dns_query_t;

typedef struct {
	uint32_t		rrttl;
	uint16_t		rrtype;
	uint16_t		rrclass;
	wreck_dns_name_t	name;
	wreck_dns_rdata_t	*rdata;
} wreck_dns_rr_t;

typedef struct {
	uint32_t		rrttl;
	uint16_t		rrtype;
	uint16_t		rrclass;
	uint16_t		n_rdatas;
	wreck_dns_name_t	name;
	wreck_dns_rdata_t	**rdatas;
} wreck_dns_rrset_t;

typedef struct {
	uint16_t		n_rrsets;
	wreck_dns_rrset_t	**rrsets;
} wreck_dns_rrset_array_t;

typedef struct {
	uint16_t		id;
	uint16_t		flags;
	wreck_dns_qrr_t		question;
	wreck_dns_rrset_array_t	answer;
	wreck_dns_rrset_array_t	authority;
	wreck_dns_rrset_array_t	additional;
} wreck_dns_message_t;

char *	wreck_name_to_str(wreck_dns_name_t *name);
char *	wreck_rdata_to_str(wreck_dns_rdata_t *rdata, uint16_t rrtype, uint16_t rrclass);
size_t	wreck_domain_to_str(const uint8_t *src, char *dst);
size_t	wreck_name_skip(const uint8_t **data, const uint8_t *eod);
void	wreck_print_question_record(FILE *fp, wreck_dns_qrr_t *q);
void	wreck_print_rr(FILE *fp, uint8_t *dname,
		       uint16_t rrtype, uint16_t rrclass, uint32_t rrttl,
		       uint16_t rdlen, const uint8_t *rdata);
void	wreck_print_data(const uint8_t *p, size_t len);
void	wreck_print_message(FILE *fp, wreck_dns_message_t *m);
void	wreck_print_rrset(FILE *fp, wreck_dns_rrset_t *rrset);
void	wreck_print_rrset_array(FILE *fp, wreck_dns_rrset_array_t *a);

void	wreck_dns_message_clear(wreck_dns_message_t *m);
void	wreck_dns_rr_clear(wreck_dns_rr_t *rr);
void	wreck_dns_rrset_clear(wreck_dns_rrset_t *rrset);
void	wreck_dns_rrset_array_clear(wreck_dns_rrset_array_t *a);

wreck_status	wreck_name_len_uncomp(const uint8_t *p, const uint8_t *eop, size_t *sz);
wreck_status	wreck_name_unpack(const uint8_t *p, const uint8_t *eop, const uint8_t *src,
				  uint8_t *dst, size_t *sz);
wreck_status	wreck_parse_message(const uint8_t *op, const uint8_t *eop,
				    wreck_dns_message_t *m);
wreck_status	wreck_parse_message_rr(const uint8_t *p, const uint8_t *eop, const uint8_t *data,
				       size_t *rrsz, wreck_dns_rr_t *rr);
wreck_status	wreck_parse_question_record(const uint8_t *q, const uint8_t *eoq,
					    wreck_dns_qrr_t *question);
wreck_status	wreck_parse_rdata(const uint8_t *p, const uint8_t *eop, const uint8_t *ordata,
				  uint16_t rrtype, uint16_t rrclass, uint16_t rdlen,
				  size_t *alloc_bytes, uint8_t *dst);
wreck_status	wreck_parse_header(const uint8_t *p, size_t len, uint16_t *id, uint16_t *flags,
				   uint16_t *qdcount, uint16_t *ancount,
				   uint16_t *nscount, uint16_t *arcount);
