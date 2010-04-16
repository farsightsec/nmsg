#include "private.h"

void
wdns_print_message(FILE *fp, wdns_message_t *m)
{
	char *s;

	s = wdns_message_to_str(m);
	if (s == NULL)
		return;
	fputs(s, fp);
	free(s);
}
