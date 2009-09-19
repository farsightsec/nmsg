#include "private.h"

void
wdns_print_message(FILE *fp, wdns_message_t *m)
{
	char *name;
	const char *dns_class;

	fprintf(fp, "; Printing message @ %p\n", m);
	fprintf(fp, ";; header: id=%#02hx opcode=%hu rcode=%hu\n", m->id,
		WDNS_FLAGS_OPCODE(m->flags),
		WDNS_FLAGS_RCODE(m->flags)
	);
	fprintf(fp, ";; flags: qr=%u aa=%u tc=%u rd=%u ra=%u z=%u ad=%u cd=%u\n\n",
		WDNS_FLAGS_QR(m->flags),
		WDNS_FLAGS_AA(m->flags),
		WDNS_FLAGS_TC(m->flags),
		WDNS_FLAGS_RD(m->flags),
		WDNS_FLAGS_RA(m->flags),
		WDNS_FLAGS_Z(m->flags),
		WDNS_FLAGS_AD(m->flags),
		WDNS_FLAGS_CD(m->flags)
	);

	fprintf(fp, ";; QUESTION SECTION:\n");
	name = wdns_name_to_str(&m->question.name);
	fprintf(fp, ";%s ", name);
	free(name);
	dns_class = wdns_class_to_str(m->question.rrclass);
	if (dns_class)
		fprintf(fp, "%s ", dns_class);
	else
		fprintf(fp, "CLASS%u ", m->question.rrclass);
	fprintf(fp, "TYPE%u\n", m->question.rrtype);

	fprintf(fp, "\n;; ANSWER SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ANSWER]);

	fprintf(fp, "\n;; AUTHORITY SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_AUTHORITY]);

	fprintf(fp, "\n;; ADDITIONAL SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ADDITIONAL]);

	fprintf(fp, "\n");
}
