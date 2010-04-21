#include "private.h"

/**
 * Convert a domain name to a human-readable string.
 *
 * \param[in] src domain name in wire format
 * \param[in] src_len length of domain name in bytes
 * \param[out] dst caller-allocated string buffer of size WDNS_PRESLEN_NAME
 * 
 * \return Number of bytes read from src.
 */

size_t
wdns_domain_to_str(const uint8_t *src, size_t src_len, char *dst)
{
	size_t bytes_read = 0;
	size_t bytes_remaining = src_len;
	uint8_t oclen;

	assert(src != NULL);

	oclen = *src;
	while (bytes_remaining > 0 && oclen != 0) {
		src++;
		bytes_remaining--;

		bytes_read += oclen + 1 /* length octet */;

		while (oclen-- && bytes_remaining > 0) {
			uint8_t c = *src++;
			bytes_remaining--;

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
