#include "private.h"

void
wdns_print_rrset(FILE *fp, wdns_rrset_t *rrset)
{
	char *name;
	wdns_rdata_t *rdata;

	name = wdns_name_to_str(&rrset->name);

	for (unsigned i = 0; i < rrset->n_rdatas; i++) {
		rdata = rrset->rdatas[i];

		fprintf(fp, "%s %u CLASS%u TYPE%u \\# ", name,
			rrset->rrttl, rrset->rrclass, rrset->rrtype);
		fprintf(fp, "%u ", rdata->len);
		for (unsigned j = 0; j < rdata->len; j++)
			fprintf(fp, "%02x ", rdata->data[j]);
		fprintf(fp, "\n");
	}

	free(name);
}

void
wdns_print_rrset_array(FILE *fp, wdns_rrset_array_t *a)
{
	for (unsigned i = 0; i < a->n_rrsets; i++)
		wdns_print_rrset(fp, a->rrsets[i]);
}

void
wdns_print_message(FILE *fp, wdns_message_t *m)
{
	char *name;

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
	fprintf(fp, ";%s CLASS%u TYPE%u\n",
		name, m->question.rrclass, m->question.rrtype);
	free(name);

	fprintf(fp, "\n;; ANSWER SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ANSWER]);

	fprintf(fp, "\n;; AUTHORITY SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_AUTHORITY]);

	fprintf(fp, "\n;; ADDITIONAL SECTION:\n");
	wdns_print_rrset_array(fp, &m->sections[WDNS_MSG_SEC_ADDITIONAL]);

	fprintf(fp, "\n");
}
