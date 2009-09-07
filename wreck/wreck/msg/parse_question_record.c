#include "private.h"

/**
 * Parse a DNS question record.
 *
 * \param[in] q pointer to start of question record
 * \param[in] eoq end of buffer containing question record
 * \param[out] question output object
 *
 * \return wreck_msg_success
 * \return wreck_msg_err_parse_error
 * \return wreck_msg_err_malloc
 */

wreck_msg_status
wreck_parse_question_record(const uint8_t *q, const uint8_t *eoq, wreck_dns_qrr_t *question)
{
	const uint8_t *p = q;
	uint32_t len = eoq - q;
	size_t nlen;
	wreck_msg_status status;

	/* find length of qname */
	status = wreck_name_len_uncomp(p, eoq, &nlen);
	if (status != wreck_msg_success)
		WRECK_ERROR(wreck_msg_err_parse_error);

	if (nlen > WRECK_DNS_MAXLEN_NAME)
		WRECK_ERROR(wreck_msg_err_name_len);

	question->rrname.len = (uint16_t) nlen;
	WRECK_BUF_ADVANCE(p, len, question->rrname.len);

	/* copy qtype and qclass */
	if (len < 4)
		WRECK_ERROR(wreck_msg_err_parse_error);
	WRECK_BUF_GET16(question->rrtype, p);
	WRECK_BUF_GET16(question->rrclass, p);

	/* copy qname */
	question->rrname.data = malloc(question->rrname.len);
	if (question->rrname.data == NULL)
		WRECK_ERROR(wreck_msg_err_malloc);
	memcpy(question->rrname.data, q, question->rrname.len);

	return (wreck_msg_success);
}
