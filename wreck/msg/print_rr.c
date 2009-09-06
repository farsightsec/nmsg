#include "private.h"

/**
 * Print a resource record in human-readable form.
 *
 * \param[in] fp the FILE to print to
 */

void
wreck_print_rr(FILE *fp, uint8_t *dname,
	       uint16_t rrtype, uint16_t rrclass, uint32_t rrttl,
	       uint16_t rdlen, const uint8_t *rdata)
{
	char name[WRECK_DNS_MAXLEN_NAME];

	wreck_domain_to_str(dname, name);
	fprintf(fp, "  oname=%s\n", name);
	fprintf(fp, "  type=%hu (%#.2hx) class=%hu (%#.2hx) ttl=%u (%#.4x) rdlen=%hu",
		rrtype, rrtype, rrclass, rrclass, rrttl, rrttl, rdlen);
	for (int i = 0; i < rdlen; i++) {
		if ((i % 23) == 0)
			fprintf(fp, "\n  rdata = ");
		fprintf(fp, "%02x ", rdata[i]);
	}
	fprintf(fp, "\n");
}
