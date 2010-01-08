#include "private.h"

void
wdns_print_message(FILE *fp, wdns_message_t *m)
{
	fprintf(fp, ";; ->>HEADER<<- opcode: %hu rcode: %hu id: %hu\n",
		WDNS_FLAGS_OPCODE(*m),
		WDNS_FLAGS_RCODE(*m),
		m->id
	);
	fprintf(fp, ";; flags:%s%s%s%s%s%s%s;\n",
		WDNS_FLAGS_QR(*m) ? " qr" : "",
		WDNS_FLAGS_AA(*m) ? " aa" : "",
		WDNS_FLAGS_TC(*m) ? " tc" : "",
		WDNS_FLAGS_RD(*m) ? " rd" : "",
		WDNS_FLAGS_RA(*m) ? " ra" : "",
		WDNS_FLAGS_AD(*m) ? " ad" : "",
		WDNS_FLAGS_CD(*m) ? " cd" : ""
	);

	fprintf(fp, "\n;; QUESTION SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_QUESTION], WDNS_MSG_SEC_QUESTION);

	fprintf(fp, "\n;; ANSWER SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ANSWER], WDNS_MSG_SEC_ANSWER);

	fprintf(fp, "\n;; AUTHORITY SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_AUTHORITY], WDNS_MSG_SEC_AUTHORITY);

	fprintf(fp, "\n;; ADDITIONAL SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ADDITIONAL], WDNS_MSG_SEC_ADDITIONAL);

	fprintf(fp, "\n");
}
