#include "private.h"

char *
wdns_message_to_str(wdns_message_t *m)
{
	char *ret;
	const char *opcode;
	const char *rcode;
	Ustr *s;

	s = ustr_dup_empty();
	
	ustr_add_cstr(&s, ";; ->>HEADER<<- ");

	opcode = wdns_opcode_to_str(WDNS_FLAGS_OPCODE(*m));
	if (opcode != NULL)
		ustr_add_fmt(&s, "opcode: %s", opcode);
	else
		ustr_add_fmt(&s, "opcode: %hu", WDNS_FLAGS_OPCODE(*m));

	rcode = wdns_rcode_to_str(WDNS_FLAGS_RCODE(*m));
	if (rcode != NULL)
		ustr_add_fmt(&s, ", rcode: %s", rcode);
	else
		ustr_add_fmt(&s, ", rcode: %hu", WDNS_FLAGS_RCODE(*m));

	ustr_add_fmt(&s,
		     ", id: %hu\n"
		     ";; flags:%s%s%s%s%s%s%s; "
		     "QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n",
		     m->id,
		     WDNS_FLAGS_QR(*m) ? " qr" : "",
		     WDNS_FLAGS_AA(*m) ? " aa" : "",
		     WDNS_FLAGS_TC(*m) ? " tc" : "",
		     WDNS_FLAGS_RD(*m) ? " rd" : "",
		     WDNS_FLAGS_RA(*m) ? " ra" : "",
		     WDNS_FLAGS_AD(*m) ? " ad" : "",
		     WDNS_FLAGS_CD(*m) ? " cd" : "",
		     m->sections[0].n_rrs,
		     m->sections[1].n_rrs,
		     m->sections[2].n_rrs,
		     m->sections[3].n_rrs
	);

	ustr_add_cstr(&s, "\n;; QUESTION SECTION:\n");
	_wdns_rrset_array_to_ustr(&s, &m->sections[WDNS_MSG_SEC_QUESTION], WDNS_MSG_SEC_QUESTION);

	ustr_add_cstr(&s, "\n;; ANSWER SECTION:\n");
	_wdns_rrset_array_to_ustr(&s, &m->sections[WDNS_MSG_SEC_ANSWER], WDNS_MSG_SEC_ANSWER);

	ustr_add_cstr(&s, "\n;; AUTHORITY SECTION:\n");
	_wdns_rrset_array_to_ustr(&s, &m->sections[WDNS_MSG_SEC_AUTHORITY], WDNS_MSG_SEC_AUTHORITY);

	ustr_add_cstr(&s, "\n;; ADDITIONAL SECTION:\n");
	_wdns_rrset_array_to_ustr(&s, &m->sections[WDNS_MSG_SEC_ADDITIONAL], WDNS_MSG_SEC_ADDITIONAL);

	if (ustr_enomem(s)) {
		ustr_free(s);
		return (NULL);
	}
	ret = strdup(ustr_cstr(s));
	ustr_free(s);
	return (ret);
}
