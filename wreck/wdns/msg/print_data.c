#include "private.h"

void
wdns_print_data(const uint8_t *p, size_t len)
{
	printf("printing data, len=%zu\n", len);
	while (len-- != 0)
		printf("%02x", *(p++));
	printf("\n");
}
