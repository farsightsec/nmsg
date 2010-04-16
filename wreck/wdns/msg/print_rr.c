#include "private.h"

void
wdns_print_rr(FILE *fp, wdns_rr_t *rr, unsigned sec)
{
	char *s;

	s = wdns_rr_to_str(rr, sec);
	if (s == NULL)
		return;
	fputs(s, fp);
	free(s);
}
