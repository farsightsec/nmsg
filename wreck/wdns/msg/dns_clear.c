#include "private.h"

void
wdns_dns_query_clear(wdns_dns_query_t *q)
{
	free(q->question.name.data);
}

void
wdns_dns_rr_clear(wdns_dns_rr_t *rr)
{
	free(rr->name.data);
	free(rr->rdata);

	rr->name.data = NULL;
	rr->rdata = NULL;
}

void
wdns_dns_rrset_clear(wdns_dns_rrset_t *rrset)
{
	for (unsigned i = 0; i < rrset->n_rdatas; i++)
		free(rrset->rdatas[i]);
	free(rrset->name.data);
	free(rrset->rdatas);
}

void
wdns_dns_rrset_array_clear(wdns_dns_rrset_array_t *a)
{
	for (unsigned i = 0; i < a->n_rrsets; i++) {
		wdns_dns_rrset_clear(a->rrsets[i]);
		free(a->rrsets[i]);
	}
	free(a->rrsets);
	a->n_rrsets = 0;
}

void
wdns_dns_message_clear(wdns_dns_message_t *m)
{
	free(m->question.name.data);
	for (unsigned i = 0; i < WDNS_MSG_SEC_MAX; i++)
		wdns_dns_rrset_array_clear(&m->sections[i]);
}
