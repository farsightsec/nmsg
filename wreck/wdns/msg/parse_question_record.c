#include "private.h"

/**
 * Parse a DNS question record.
 *
 * \param[in] q pointer to start of question record
 * \param[in] eoq end of buffer containing question record
 * \param[out] question output object
 *
 * \return wdns_msg_success
 * \return wdns_msg_err_parse_error
 * \return wdns_msg_err_malloc
 */

wdns_msg_status
wdns_parse_question_record(const uint8_t *q, const uint8_t *eoq, wdns_dns_qrr_t *question)
{
	const uint8_t *p = q;
	uint32_t len = eoq - q;
	size_t nlen;
	wdns_msg_status status;

	/* find length of qname */
	status = wdns_name_len_uncomp(p, eoq, &nlen);
	if (status != wdns_msg_success)
		WDNS_ERROR(wdns_msg_err_parse_error);

	if (nlen > WDNS_MAXLEN_NAME)
		WDNS_ERROR(wdns_msg_err_name_len);

	question->name.len = (uint16_t) nlen;
	WDNS_BUF_ADVANCE(p, len, question->name.len);

	/* copy qtype and qclass */
	if (len < 4)
		WDNS_ERROR(wdns_msg_err_parse_error);
	WDNS_BUF_GET16(question->rrtype, p);
	WDNS_BUF_GET16(question->rrclass, p);

	/* copy qname */
	question->name.data = malloc(question->name.len);
	if (question->name.data == NULL)
		WDNS_ERROR(wdns_msg_err_malloc);
	memcpy(question->name.data, q, question->name.len);

	return (wdns_msg_success);
}
