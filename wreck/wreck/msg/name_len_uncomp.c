#include "private.h"

/**
 * Determine the length of an uncompressed wire format domain name.
 *
 * \param[in] p pointer to uncompressed domain name
 * \param[in] eop pointer to end of buffer containing name
 * \param[out] sz length of name
 *
 * \return wreck_msg_success
 * \return wreck_msg_err_overflow
 * \return wreck_msg_err_invalid_length_octet
 */

wreck_msg_status
wreck_name_len_uncomp(const uint8_t *p, const uint8_t *eop, size_t *sz)
{
	uint32_t olen = eop - p;
	uint32_t len = olen;

	if (p >= eop)
		WRECK_ERROR(wreck_msg_err_overflow);

	while (len-- != 0) {
		uint8_t oclen;
		WRECK_BUF_GET8(oclen, p);

		if (oclen > 63 || oclen > len)
			WRECK_ERROR(wreck_msg_err_invalid_length_octet);
		if (oclen == 0)
			break;

		WRECK_BUF_ADVANCE(p, len, oclen);
	}

	if (*p != 0)
		WRECK_ERROR(wreck_msg_err_overflow);

	*sz = olen - len;
	return (wreck_msg_success);
}
