#include "private.h"

wdns_msg_status
_wdns_parse_header(const uint8_t *p, size_t len, uint16_t *id, uint16_t *flags,
		   uint16_t *qdcount, uint16_t *ancount, uint16_t *nscount, uint16_t *arcount)
{
	if (len < WDNS_LEN_HEADER)
		WDNS_ERROR(wdns_msg_err_len);

	*id = htons(*((uint16_t *) p));
	*flags = htons(*((uint16_t *) (p + 2)));
	*qdcount = htons(*((uint16_t *) (p + 4)));
	*ancount = htons(*((uint16_t *) (p + 6)));
	*nscount = htons(*((uint16_t *) (p + 8)));
	*arcount = htons(*((uint16_t *) (p + 10)));

	return (wdns_msg_success);
}
