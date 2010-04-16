#include "private.h"

void
_wdns_rrset_to_ustr(Ustr **s, wdns_rrset_t *rrset, unsigned sec)
{
	unsigned n_rdatas;

	if (sec == WDNS_MSG_SEC_QUESTION)
		n_rdatas = 1;
	else
		n_rdatas = rrset->n_rdatas;

	for (unsigned i = 0; i < n_rdatas; i++) {
		wdns_rr_t rr;
		rr.rrttl = rrset->rrttl;
		rr.rrtype = rrset->rrtype;
		rr.rrclass = rrset->rrclass;
		rr.name.len = rrset->name.len;
		rr.name.data = rrset->name.data;
		rr.rdata = rrset->rdatas[i];
		_wdns_rr_to_ustr(s, &rr, sec);
	}
}
