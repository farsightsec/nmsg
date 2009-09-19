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
