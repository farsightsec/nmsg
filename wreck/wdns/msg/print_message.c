#include "private.h"

void
wreck_print_rrset(FILE *fp, wreck_dns_rrset_t *rrset)
{
	char *name;
	wreck_dns_rdata_t *rdata;

	name = wreck_name_to_str(&rrset->name);

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
wreck_print_rrset_array(FILE *fp, wreck_dns_rrset_array_t *a)
{
	for (unsigned i = 0; i < a->n_rrsets; i++)
		wreck_print_rrset(fp, a->rrsets[i]);
}

void
wreck_print_message(FILE *fp, wreck_dns_message_t *m)
{
	char *name;

	fprintf(fp, "; Printing message @ %p\n", m);
	fprintf(fp, ";; header: id=%#02hx opcode=%hu rcode=%hu\n", m->id,
		WRECK_DNS_FLAGS_OPCODE(m->flags),
		WRECK_DNS_FLAGS_RCODE(m->flags)
	);
	fprintf(fp, ";; flags: qr=%u aa=%u tc=%u rd=%u ra=%u z=%u ad=%u cd=%u\n\n",
		WRECK_DNS_FLAGS_QR(m->flags),
		WRECK_DNS_FLAGS_AA(m->flags),
		WRECK_DNS_FLAGS_TC(m->flags),
		WRECK_DNS_FLAGS_RD(m->flags),
		WRECK_DNS_FLAGS_RA(m->flags),
		WRECK_DNS_FLAGS_Z(m->flags),
		WRECK_DNS_FLAGS_AD(m->flags),
		WRECK_DNS_FLAGS_CD(m->flags)
	);

	fprintf(fp, ";; QUESTION SECTION:\n");
	name = wreck_name_to_str(&m->question.name);
	fprintf(fp, ";%s CLASS%u TYPE%u\n",
		name, m->question.rrclass, m->question.rrtype);
	free(name);

	fprintf(fp, "\n;; ANSWER SECTION:\n");
	wreck_print_rrset_array(fp, &m->sections[WRECK_MSG_SEC_ANSWER]);

	fprintf(fp, "\n;; AUTHORITY SECTION:\n");
	wreck_print_rrset_array(fp, &m->sections[WRECK_MSG_SEC_AUTHORITY]);

	fprintf(fp, "\n;; ADDITIONAL SECTION:\n");
	wreck_print_rrset_array(fp, &m->sections[WRECK_MSG_SEC_ADDITIONAL]);

	fprintf(fp, "\n");
}
