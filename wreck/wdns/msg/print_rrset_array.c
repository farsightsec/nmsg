#include "private.h"

void
wdns_print_rrset_array(FILE *fp, wdns_rrset_array_t *rr, unsigned sec)
{
	char *s;

	s = wdns_rrset_array_to_str(rr, sec);
	if (s == NULL)
		return;
	fputs(s, fp);
	free(s);
}
