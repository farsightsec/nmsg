#include "private.h"

/**
 * Print a resource record in human-readable form.
 *
 * \param[in] fp the FILE to print to
 */

void
wdns_print_rr(FILE *fp, wdns_rr_t *rr, unsigned sec)
{
	const char *dns_class, *dns_type;
	char name[WDNS_PRESLEN_NAME];

	wdns_domain_to_str(rr->name.data, name);
	dns_class = wdns_rrclass_to_str(rr->rrclass);
	dns_type = wdns_rrtype_to_str(rr->rrtype);

	if (sec == WDNS_MSG_SEC_QUESTION)
		fputc(';', fp);

	fputs(name, fp);

	if (sec != WDNS_MSG_SEC_QUESTION)
		fprintf(fp, " %u", rr->rrttl);

	if (dns_class)
		fprintf(fp, " %s", dns_class);
	else
		fprintf(fp, " CLASS%u", rr->rrclass);

	if (dns_type)
		fprintf(fp, " %s", dns_type);
	else
		fprintf(fp, " TYPE%u", rr->rrtype);

	if (sec != WDNS_MSG_SEC_QUESTION) {
		char *buf;
		size_t bufsz;
		wdns_msg_status status;

		status = wdns_rdata_to_str(rr->rdata->data, rr->rdata->len,
					   rr->rrtype, rr->rrclass,
					   NULL, &bufsz);
		if (status != wdns_msg_success) {
			fprintf(fp, " ### PARSE ERROR #%u ###\n", status);
			return;
		}
		buf = alloca(bufsz);
		wdns_rdata_to_str(rr->rdata->data, rr->rdata->len,
				  rr->rrtype, rr->rrclass,
				  buf, NULL);
		fputs(" ", fp);
		fputs(buf, fp);
	}
	fputs("\n", fp);
}
