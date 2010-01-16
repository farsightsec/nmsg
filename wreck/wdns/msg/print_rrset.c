#include "private.h"

void
wdns_print_rrset(FILE *fp, wdns_rrset_t *rrset, unsigned sec)
{
	char *s;

	s = wdns_rrset_to_str(rrset, sec);
	if (s == NULL)
		return;
	fputs(s, fp);
	free(s);
}
