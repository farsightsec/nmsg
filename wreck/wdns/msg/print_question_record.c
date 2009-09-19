#include "private.h"

/**
 * Print a question record in human-readable form.
 *
 * \param[in] fp the FILE to print to
 * \param[in] q the question record
 */

void
wdns_print_question_record(FILE *fp, wdns_qrr_t *q)
{
	char name[WDNS_MAXLEN_NAME];

	wdns_domain_to_str(q->name.data, name);
	fprintf(fp, "  qname=%s\n", name);
	fprintf(fp, "  qtype=%hu (%#.2hx) qclass=%hu (%#.2hx)\n",
		q->rrtype, q->rrtype, q->rrclass, q->rrclass);
}
