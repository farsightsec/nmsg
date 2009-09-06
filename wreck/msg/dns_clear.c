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
wreck_dns_rrset_array_clear(wreck_dns_rrset_array_t *a)
{
	for (unsigned i = 0; i < a->n_rrsets; i++) {
		for (unsigned j = 0; j < a->rrsets[i]->n_rdatas; j++) {
			free(a->rrsets[i]->rdatas[j]);
		}
		free(a->rrsets[i]->name.data);
		free(a->rrsets[i]->rdatas);
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
