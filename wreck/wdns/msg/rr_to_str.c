#include "private.h"

char *
wdns_rr_to_str(wdns_rr_t *rr, unsigned sec)
{
	char *ret;
	Ustr *s;

	s = ustr_dup_empty();
	_wdns_rr_to_ustr(&s, rr, sec);
	if (ustr_enomem(s)) {
		ustr_free(s);
		return (NULL);
	}
	ret = strdup(ustr_cstr(s));
	ustr_free(s);
	return (ret);
}
