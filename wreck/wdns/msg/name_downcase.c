#include "private.h"

/**
 * Downcase a wdns_name_t.
 *
 * \param[in] name the name to downcase
 */

void
wdns_name_downcase(wdns_name_t *name)
{
	uint8_t *p = name->data;
	uint16_t len = name->len;

	while (len-- != 0) {
		if (isascii(*p) && isupper(*p))
			*p = tolower(*p);
		p++;
	}
}
