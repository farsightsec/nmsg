#include "private.h"

static int
rdata_cmp(const void *e1, const void *e2)
{
	const wdns_rdata_t *r1 = *((wdns_rdata_t **) e1);
	const wdns_rdata_t *r2 = *((wdns_rdata_t **) e2);

	if (r1->len < r2->len) {
		return (-1);
	} else if (r1->len > r2->len) {
		return (1);
	} else {
		return (memcmp(r1->data, r2->data, r1->len));
	}
}

/**
 * Sort the rdata set of an RRset.
 *
 * \return wdns_msg_success
 */

wdns_msg_status
wdns_sort_rrset(wdns_rrset_t *rrset)
{
	if (rrset->n_rdatas > 1)
		qsort(&rrset->rdatas[0],
		      rrset->n_rdatas,
		      sizeof(rrset->rdatas[0]),
		      rdata_cmp);
	return (wdns_msg_success);
}
