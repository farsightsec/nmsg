#include "private.h"

void
wdns_print_message(FILE *fp, wdns_message_t *m)
{
	fprintf(fp, "; Printing message @ %p\n", m);
	fprintf(fp, ";; header: id=%#02hx opcode=%hu rcode=%hu\n", m->id,
		WDNS_FLAGS_OPCODE(*m),
		WDNS_FLAGS_RCODE(*m)
	);
	fprintf(fp, ";; flags: qr=%u aa=%u tc=%u rd=%u ra=%u z=%u ad=%u cd=%u\n\n",
		WDNS_FLAGS_QR(*m),
		WDNS_FLAGS_AA(*m),
		WDNS_FLAGS_TC(*m),
		WDNS_FLAGS_RD(*m),
		WDNS_FLAGS_RA(*m),
		WDNS_FLAGS_Z(*m),
		WDNS_FLAGS_AD(*m),
		WDNS_FLAGS_CD(*m)
	);

	fprintf(fp, ";; QUESTION SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_QUESTION], WDNS_MSG_SEC_QUESTION);

	fprintf(fp, "\n;; ANSWER SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ANSWER], WDNS_MSG_SEC_ANSWER);

	fprintf(fp, "\n;; AUTHORITY SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_AUTHORITY], WDNS_MSG_SEC_AUTHORITY);

	fprintf(fp, "\n;; ADDITIONAL SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ADDITIONAL], WDNS_MSG_SEC_ADDITIONAL);

	fprintf(fp, "\n");
}
