#include "private.h"

/**
 * Convert a domain name to a human-readable string.
 *
 * \param[in] src domain name in wire format
 * \param[out] dst caller-allocated string buffer
 * 
 * \return Number of bytes read from src.
 */

size_t
wdns_domain_to_str(const uint8_t *src, char *dst)
{
	size_t bytes_read = 0;
	uint8_t oclen;

	oclen = *src;
	while (oclen != 0) {
		src++;

		bytes_read += oclen + 1 /* length octet */;

		while (oclen--) {
			uint8_t c = *src++;

			if (c == '.') {
				*dst++ = '\\';
				*dst++ = c;
			} else if (c >= '!' && c <= '~') {
				*dst++ = c;
			} else {
				snprintf(dst, 5, "\\%.3d", c);
				dst += 4;
			}
		}
		*dst++ = '.';
		oclen = *src;
	}
	if (bytes_read == 0)
		*dst++ = '.';
	bytes_read++;

	*dst = '\0';
	return (bytes_read);
}
