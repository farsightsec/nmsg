#include "private.h"

char *
wdns_rrset_to_str(wdns_rrset_t *rrset, unsigned sec)
{
	char *ret;
	Ustr *s;

	s = ustr_dup_empty();
	_wdns_rrset_to_ustr(&s, rrset, sec);
	if (ustr_enomem(s)) {
		ustr_free(s);
		return (NULL);
	}
	ret = strdup(ustr_cstr(s));
	ustr_free(s);
	return (ret);
}
