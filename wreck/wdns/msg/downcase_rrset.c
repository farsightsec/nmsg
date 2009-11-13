#include "private.h"

wdns_msg_status
wdns_downcase_rrset(wdns_rrset_t *rrset)
{
	wdns_msg_status status;

	wdns_downcase_name(&rrset->name);
	for (int i = 0; i < rrset->n_rdatas; i++) {
		if (rrset->rdatas[i] != NULL) {
			status = wdns_downcase_rdata(rrset->rdatas[i],
						     rrset->rrtype, rrset->rrclass);
			if (status != wdns_msg_success)
				return (status);
		}
	}

	return (wdns_msg_success);
}
