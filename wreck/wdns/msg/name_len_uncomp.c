#include "private.h"

/**
 * Determine the length of an uncompressed wire format domain name.
 *
 * \param[in] p pointer to uncompressed domain name
 * \param[in] eop pointer to end of buffer containing name
 * \param[out] sz length of name
 *
 * \return wdns_msg_success
 * \return wdns_msg_err_overflow
 * \return wdns_msg_err_invalid_length_octet
 */

wdns_msg_status
wdns_name_len_uncomp(const uint8_t *p, const uint8_t *eop, size_t *sz)
{
	uint32_t olen = eop - p;
	uint32_t len = olen;

	if (p >= eop)
		WDNS_ERROR(wdns_msg_err_overflow);

	while (len-- != 0) {
		uint8_t oclen;
		WDNS_BUF_GET8(oclen, p);

		if (oclen > 63 || oclen > len)
			WDNS_ERROR(wdns_msg_err_invalid_length_octet);
		if (oclen == 0)
			break;

		WDNS_BUF_ADVANCE(p, len, oclen);
	}

	if (*p != 0)
		WDNS_ERROR(wdns_msg_err_overflow);

	*sz = olen - len;
	return (wdns_msg_success);
}
