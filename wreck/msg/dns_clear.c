#include "private.h"

void
wreck_dns_rr_clear(wreck_dns_rr_t *rr)
{
	free(rr->name.data);
	free(rr->rdata);

	rr->name.data = NULL;
	rr->rdata = NULL;
}

void
wreck_dns_rrset_clear(wreck_dns_rrset_t *rrset)
{
	for (unsigned i = 0; i < rrset->n_rdatas; i++)
		free(rrset->rdatas[i]);
	free(rrset->name.data);
	free(rrset->rdatas);
}

void
wreck_dns_rrset_array_clear(wreck_dns_rrset_array_t *a)
{
	for (unsigned i = 0; i < a->n_rrsets; i++) {
		wreck_dns_rrset_clear(a->rrsets[i]);
		free(a->rrsets[i]);
	}
	free(a->rrsets);
	a->n_rrsets = 0;
}

void
wreck_dns_message_clear(wreck_dns_message_t *m)
{
	free(m->question.rrname.data);
	wreck_dns_rrset_array_clear(&m->answer);
	wreck_dns_rrset_array_clear(&m->authority);
	wreck_dns_rrset_array_clear(&m->additional);
}
