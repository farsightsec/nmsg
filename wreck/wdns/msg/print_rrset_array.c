#include "private.h"

void
wdns_print_rrset_array(FILE *fp, wdns_rrset_array_t *a, unsigned sec)
{
	for (unsigned i = 0; i < a->n_rrs; i++)
		wdns_print_rr(fp, &a->rrs[i], sec);
}
