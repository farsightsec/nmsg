#include "private.h"

/**
 * Copy an uncompressed domain name from a message.
 *
 * The caller must allocate at least #WDNS_MAXLEN_NAME bytes for
 * the destination buffer.
 *
 * \param[in] p pointer to message
 * \param[in] eop pointer to end of message
 * \param[in] src pointer to domain name
 * \param[out] dst caller-allocated buffer for domain name
 * \param[out] sz total length of domain name (may be NULL)
 *
 * \return
 */

wdns_msg_status
wdns_copy_uname(const uint8_t *p, const uint8_t *eop, const uint8_t *src,
		uint8_t *dst, size_t *sz)
{
	uint8_t c;

	size_t total_len = 0;

	if (p >= eop || src >= eop || src < p)
		return (wdns_msg_err_out_of_bounds);

	while ((c = *src++) != 0) {
		if (c <= 63) {
			total_len++;
			if (total_len >= WDNS_MAXLEN_NAME)
				return (wdns_msg_err_name_overflow);
			*dst++ = c;

			total_len += c;
			if (total_len >= WDNS_MAXLEN_NAME)
				return (wdns_msg_err_name_overflow);
			if (src + c > eop)
				return (wdns_msg_err_out_of_bounds);
			memcpy(dst, src, c);

			dst += c;
			src += c;
		} else {
			return (wdns_msg_err_invalid_length_octet);
		}
	}
	*dst = '\0';
	total_len++;

	if (sz)
		*sz = total_len;
	return (wdns_msg_success);
}
