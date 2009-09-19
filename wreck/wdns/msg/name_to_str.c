#include "private.h"

/**
 * Convert a wdns_name_t to a human-readable string.
 *
 * Caller must free the result.
 *
 * \param[in] name the name to convert
 *
 * \return formatted string, or NULL on error
 */

char *
wdns_name_to_str(wdns_name_t *name)
{
	char *p, *pres;

	uint8_t *data = name->data;
	uint16_t len = name->len;

	p = pres = malloc(len + 1);
	if (pres == NULL)
		return (NULL);

	while (len != 0) {
		uint8_t oclen = *data;
		data++;
		len--;

		if (oclen == 0)
			break;
		while (oclen--)
			*p++ = *data++;
		*p++ = '.';
	}

	if (name->len == 1 && name->data[0] == '\0') {
		p = pres;
		*p++ = '.';
	}

	*p = '\0';
	return (pres);
}
