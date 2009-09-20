#include "private.h"

void
wdns_print_rrset(FILE *fp, wdns_rrset_t *rrset, unsigned sec)
{
	const char *dns_class, *dns_type;
	char *name;
	wdns_rdata_t *rdata;

	name = wdns_name_to_str(&rrset->name);

	for (unsigned i = 0; i < rrset->n_rdatas; i++) {
		rdata = rrset->rdatas[i];
		dns_class = wdns_class_to_str(rrset->rrclass);
		dns_type = wdns_type_to_str(rrset->rrtype);

		if (sec == WDNS_MSG_SEC_QUESTION)
			fputc(';', fp);

		fputs(name, fp);

		if (sec != WDNS_MSG_SEC_QUESTION)
			fprintf(fp, " %u", rrset->rrttl);

		if (dns_class)
			fprintf(fp, " %s", dns_class);
		else
			fprintf(fp, " CLASS%u", rrset->rrclass);

		if (dns_type)
			fprintf(fp, " %s", dns_type);
		else
			fprintf(fp, " TYPE%u", rrset->rrtype);

		if (sec != WDNS_MSG_SEC_QUESTION) {
			fputs(" \\# ", fp);

			fprintf(fp, "%u ", rdata->len);
			for (unsigned j = 0; j < rdata->len; j++)
				fprintf(fp, "%02x ", rdata->data[j]);
		}
		fputs("\n", fp);
	}

	free(name);
}
