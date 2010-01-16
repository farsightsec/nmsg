#include "private.h"

char *
wdns_rrset_array_to_str(wdns_rrset_array_t *a, unsigned sec)
{
	char *ret;
	Ustr *s;

	s = ustr_dup_empty();
	_wdns_rrset_array_to_ustr(&s, a, sec);
	if (ustr_enomem(s)) {
		ustr_free(s);
		return (NULL);
	}
	ret = strdup(ustr_cstr(s));
	ustr_free(s);
	return (ret);
}
