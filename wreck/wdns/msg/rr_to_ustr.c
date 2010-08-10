#include "private.h"

void
_wdns_rr_to_ustr(Ustr **s, wdns_rr_t *rr, unsigned sec)
{
	const char *dns_class, *dns_type;
	char name[WDNS_PRESLEN_NAME];

	wdns_domain_to_str(rr->name.data, rr->name.len, name);
	dns_class = wdns_rrclass_to_str(rr->rrclass);
	dns_type = wdns_rrtype_to_str(rr->rrtype);

	if (sec == WDNS_MSG_SEC_QUESTION)
		ustr_add_cstr(s, ";");
	
	ustr_add_cstr(s, name);

	if (sec != WDNS_MSG_SEC_QUESTION)
		ustr_add_fmt(s, " %u", rr->rrttl);

	if (dns_class)
		ustr_add_fmt(s, " %s", dns_class);
	else
		ustr_add_fmt(s, " CLASS%u", rr->rrclass);

	if (dns_type)
		ustr_add_fmt(s, " %s", dns_type);
	else
		ustr_add_fmt(s, " TYPE%u", rr->rrtype);

	if (sec != WDNS_MSG_SEC_QUESTION) {
		ustr_add_cstr(s, " ");
		_wdns_rdata_to_ustr(s, rr->rdata->data, rr->rdata->len, rr->rrtype, rr->rrclass);
	}
	ustr_add_cstr(s, "\n");
}
