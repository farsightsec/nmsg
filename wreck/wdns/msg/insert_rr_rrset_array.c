#include "private.h"

/**
 * Insert an RR into an RRset array.
 *
 * This function is destructive.  No copying is performed; instead the RR's name
 * and/or rdata fields are detached from the RR and given to an RRset in the
 * RRset array.  wdns_clear_rr() is called on the RR object.
 *
 * \return wdns_msg_success
 * \return wdns_msg_err_malloc
 */

wdns_msg_status
wdns_insert_rr_rrset_array(wdns_rr_t *rr, wdns_rrset_array_t *a)
{
	bool found_rrset = false;
	wdns_rdata_t *rdata;
	wdns_rrset_t *rrset;

	/* iterate over RRset array backwards */
	for (unsigned i = a->n_rrsets; i > 0; i--) {
		rrset = &a->rrsets[i - 1];

		if (wdns_compare_rr_rrset(rr, rrset)) {
			/* this RR is part of the RRset */
			rrset->n_rdatas += 1;
			rrset->rdatas = realloc(rrset->rdatas,
						rrset->n_rdatas * sizeof(*(rrset->rdatas)));
			if (rrset->rdatas == NULL)
				WDNS_ERROR(wdns_msg_err_malloc);

			/* detach the rdata from the RR and give it to the RRset */
			rdata = rr->rdata;
			rr->rdata = NULL;
			rrset->rdatas[rrset->n_rdatas - 1] = rdata;

			/* use the lowest TTL out of the RRs for the RRset itself */
			if (rr->rrttl < rrset->rrttl)
				rrset->rrttl = rr->rrttl;

			found_rrset = true;
			break;
		}
	}

	if (found_rrset == false) {
		/* create a new RRset */
		a->n_rrsets += 1;
		a->rrsets = realloc(a->rrsets, a->n_rrsets * sizeof(wdns_rrset_t));
		if (a->rrsets == NULL)
			WDNS_ERROR(wdns_msg_err_malloc);
		rrset = &a->rrsets[a->n_rrsets - 1];

		/* copy fields from the RR */
		rrset->rrttl = rr->rrttl;
		rrset->rrtype = rr->rrtype;
		rrset->rrclass = rr->rrclass;

		/* add rdata */
		rrset->n_rdatas = 1;
		rrset->rdatas = malloc(sizeof(*(rrset->rdatas)));
		if (rrset->rdatas == NULL) {
			free(rrset);
			WDNS_ERROR(wdns_msg_err_malloc);
		}

		/* detach the owner name from the RR and give it to the RRset */
		rrset->name.len = rr->name.len;
		rrset->name.data = rr->name.data;
		rr->name.len = 0;
		rr->name.data = NULL;

		/* detach the rdata from the RR and give it to the RRset */
		rdata = rr->rdata;
		rr->rdata = NULL;
		rrset->rdatas[0] = rdata;
	}

	wdns_clear_rr(rr);
	return (wdns_msg_success);
}
