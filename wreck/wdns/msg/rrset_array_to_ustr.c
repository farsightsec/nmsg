#include "private.h"

void
_wdns_rrset_array_to_ustr(Ustr **s, wdns_rrset_array_t *a, unsigned sec)
{
	for (unsigned i = 0; i < a->n_rrs; i++)
		_wdns_rr_to_ustr(s, &a->rrs[i], sec);
}
