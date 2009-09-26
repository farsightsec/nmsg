#include "private.h"

void
wdns_clear_rr(wdns_rr_t *rr)
{
	free(rr->name.data);
	free(rr->rdata);

	rr->name.data = NULL;
	rr->rdata = NULL;
}

void
wdns_clear_rrset(wdns_rrset_t *rrset)
{
	for (unsigned i = 0; i < rrset->n_rdatas; i++)
		free(rrset->rdatas[i]);

	free(rrset->name.data);
	rrset->name.data = NULL;

	free(rrset->rdatas);
	rrset->rdatas = NULL;

	rrset->n_rdatas = 0;
}

void
wdns_clear_rrset_array(wdns_rrset_array_t *a)
{
	for (unsigned i = 0; i < a->n_rrsets; i++)
		wdns_clear_rrset(&a->rrsets[i]);
	free(a->rrsets);
	a->n_rrsets = 0;
}

void
wdns_clear_message(wdns_message_t *m)
{
	free(m->edns.options);
	m->edns.options = NULL;
	m->edns.present = false;
	for (unsigned i = 0; i < WDNS_MSG_SEC_MAX; i++)
		wdns_clear_rrset_array(&m->sections[i]);
}
