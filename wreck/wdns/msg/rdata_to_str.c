#include "private.h"

char *
wdns_rdata_to_str(const uint8_t *rdata, uint16_t rdlen,
		  uint16_t rrtype, uint16_t rrclass)
{
	char *ret;
	Ustr *s;

	s = ustr_dup_empty();
	_wdns_rdata_to_ustr(&s, rdata, rdlen, rrtype, rrclass);
	if (ustr_enomem(s)) {
		ustr_free(s);
		return (NULL);
	}
	ret = strdup(ustr_cstr(s));
	ustr_free(s);
	return (ret);
}
