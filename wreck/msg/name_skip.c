#include "private.h"

/**
 * Skip a possibly compressed domain name.
 *
 * This function will skip to the end of the buffer if a compression pointer
 * or the terminal zero octet is not found.
 *
 * \param[in,out] data start of the domain name
 * \param[in] eod end of buffer containing the domain name
 */

void
wreck_name_skip(const uint8_t **data, const uint8_t *eod)
{
	const uint8_t *src = *data;
	uint8_t c;

	while (src <= eod && (c = *src) != 0) {
		if (c >= 192) {
			/* compression pointers occupy two octets */
			src++;
			break;
		} else if (c == 0) {
			/* end of uncompressed name */
			break;
		} else {
			/* skip c octets to the end of the label, then one more to the next
			 * length octet */
			src += c + 1;
		}
	}

	/* advance to one octet beyond the end of the name */
	src++;

	if (src > eod)
		src = eod;

	*data = src;
}
