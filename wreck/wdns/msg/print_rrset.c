#include "private.h"

void
wdns_print_rrset(FILE *fp, wdns_rrset_t *rrset, unsigned sec)
{
	const char *dns_class, *dns_type;
	char name[WDNS_PRESLEN_NAME];
	unsigned n_rdatas;

	wdns_domain_to_str(rrset->name.data, name);

	if (sec == WDNS_MSG_SEC_QUESTION)
		n_rdatas = 1;
	else
		n_rdatas = rrset->n_rdatas;

	for (unsigned i = 0; i < n_rdatas; i++) {
		dns_class = wdns_rrclass_to_str(rrset->rrclass);
		dns_type = wdns_rrtype_to_str(rrset->rrtype);

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
			char *buf;
			size_t bufsz;
			wdns_msg_status status;
			wdns_rdata_t *rdata;

			rdata = rrset->rdatas[i];

			status = wdns_rdata_to_str(rdata->data, rdata->len,
						   rrset->rrtype, rrset->rrclass,
						   NULL, &bufsz);
			if (status != wdns_msg_success) {
				fprintf(fp, " ### PARSE ERROR #%u ###\n", status);
				return;
			}
			buf = alloca(bufsz);
			wdns_rdata_to_str(rdata->data, rdata->len,
					  rrset->rrtype, rrset->rrclass,
					  buf, NULL);
			fputs(" ", fp);
			fputs(buf, fp);
		}
		fputs("\n", fp);
	}
}
