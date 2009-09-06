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
	for (; *data < eod && *data != 0; (*data)++) {
		if (**data == 0)
			break;
		if (**data >= 192) {
			/* compression pointers occupy two octets */
			(*data)++;
			break;
		}
	}
	(*data)++;
}
