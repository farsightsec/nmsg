#include "private.h"

/**
 * Uncompress a domain name from a message.
 *
 * The caller must allocate at least #WRECK_DNS_MAXLEN_NAME bytes for
 * the destination buffer.
 *
 * \param[in] p pointer to message
 * \param[in] eop pointer to end of message
 * \param[in] src pointer to domain name
 * \param[out] dst caller-allocated buffer for uncompressed domain name
 * \param[out] sz total length of uncompressed domain name (may be NULL)
 *
 * \return
 */

wreck_msg_status
wreck_name_unpack(const uint8_t *p, const uint8_t *eop, const uint8_t *src,
		  uint8_t *dst, size_t *sz)
{
	const uint8_t *cptr;
	uint8_t c;

	size_t total_len = 0;

	if (p >= eop || src >= eop || src < p)
		WRECK_ERROR(wreck_msg_err_out_of_bounds);

	while ((c = *src++) != 0) {
		if (c >= 192) {
			uint16_t offset;

			if (src > eop)
				WRECK_ERROR(wreck_msg_err_out_of_bounds);
			
			/* offset is the lower 14 bits of the 2 octet sequence */
			offset = ((c & 63) << 8) + *src;

			cptr = p + offset;

			if (cptr > eop)
				WRECK_ERROR(wreck_msg_err_invalid_compression_pointer);

			if (cptr == src - 1 && (*(src - 1) == 0)) {
				/* if a compression pointer points to exactly one octet
				 * before itself, then the only valid domain name pointee
				 * is the zero-octet root label. */
				src = cptr;
			} else if (cptr > src - 2) {
				WRECK_ERROR(wreck_msg_err_invalid_compression_pointer);
			} else {
				src = cptr;
			}
		} else if (c <= 63) {
			total_len++;
			if (total_len >= WRECK_DNS_MAXLEN_NAME)
				WRECK_ERROR(wreck_msg_err_name_overflow);
			*dst++ = c;

			total_len += c;
			if (total_len >= WRECK_DNS_MAXLEN_NAME)
				WRECK_ERROR(wreck_msg_err_name_overflow);
			if (src + c > eop)
				WRECK_ERROR(wreck_msg_err_out_of_bounds);
			memcpy(dst, src, c);

			dst += c;
			src += c;
		} else {
			WRECK_ERROR(wreck_msg_err_invalid_length_octet);
		}
	}
	*dst = '\0';
	total_len++;

	if (sz)
		*sz = total_len;
	return (wreck_msg_success);
}
