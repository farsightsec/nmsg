#include "private.h"

void
_wdns_rr_to_ustr(Ustr **s, wdns_rr_t *rr, unsigned sec)
{
	const char *dns_class, *dns_type;
	char name[WDNS_PRESLEN_NAME];

	wdns_domain_to_str(rr->name.data, name);
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
		char *buf;
		size_t bufsz;
		wdns_msg_status status;

		status = wdns_rdata_to_str(rr->rdata->data, rr->rdata->len,
					   rr->rrtype, rr->rrclass,
					   NULL, &bufsz);
		if (status != wdns_msg_success) {
			ustr_add_fmt(s, " ### PARSE ERROR #%u ###\n", status);
			return;
		}
		buf = alloca(bufsz);
		wdns_rdata_to_str(rr->rdata->data, rr->rdata->len,
				  rr->rrtype, rr->rrclass,
				  buf, NULL);
		ustr_add_cstr(s, " ");
		ustr_add_cstr(s, buf);
	}
	ustr_add_cstr(s, "\n");
}
