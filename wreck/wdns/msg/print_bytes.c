#include "private.h"

void
wdns_print_bytes(FILE *fp, uint8_t *p, size_t len)
{
	while (len-- != 0)
		fprintf(fp, "%02x", *(p++));
}
