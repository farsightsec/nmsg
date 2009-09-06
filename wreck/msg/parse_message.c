#include "private.h"

wreck_status
wreck_parse_message(const uint8_t *op, const uint8_t *eop, wreck_dns_response_t *r)
{
	const uint8_t *p = op;
	size_t n, rrlen;
	uint16_t qdcount, ancount, nscount, arcount;
	uint32_t len = eop - op;
	wreck_status status;

	if (len < WRECK_DNS_LEN_HEADER)
		WRECK_ERROR(wreck_err_len);

	WRECK_BUF_GET16(r->id, p);
	WRECK_BUF_GET16(r->flags, p);
	WRECK_BUF_GET16(qdcount, p);
	WRECK_BUF_GET16(ancount, p);
	WRECK_BUF_GET16(nscount, p);
	WRECK_BUF_GET16(arcount, p);

	len -= WRECK_DNS_LEN_HEADER;

	r->question.rrname.data = NULL;

	VERBOSE("Parsing DNS message id=%#.2x flags=%#.2x "
		"qd=%u an=%u ns=%u ar=%u\n",
		r->id, r->flags, qdcount, ancount, nscount, arcount);

	if (qdcount == 1) {
		status = wreck_parse_question_record(p, eop, &r->question);
		if (status != wreck_success)
			WRECK_ERROR(wreck_err_parse_error);
#if DEBUG
		VERBOSE("QUESTION RR\n");
		wreck_print_question_record(stdout, &r->question);
#endif
		/* skip qname */
		WRECK_BUF_ADVANCE(p, len, r->question.rrname.len);

		/* skip qtype and qclass */
		WRECK_BUF_ADVANCE(p, len, 4);

		if (ancount == 0 && nscount == 0 && arcount == 0) {
			/* if there are no more records to parse then this must be
			 * the end of the packet */
			if (p == eop) {
				return (wreck_success);
			} else {
				VERBOSE("WARNING: trailing garbage p=%p eop=%p\n", p, eop);
				//free(r->question.rrname.data);
				//WRECK_ERROR(wreck_err_parse_error);
			}
		}
	} else if (qdcount > 1) {
		WRECK_ERROR(wreck_err_parse_error);
	}

	/*
	if (p >= eop) {
		if (DNS_FLAGS_TC(r->flags)) {
			count_parse_success_wreck++;
			return (DNS_ERR_SUCCESS);
		} else {
			free(r->question.rrname.data);
			ERROR(DNS_ERR_LEN);
		}
	}
	*/

	for (n = 0; n < ancount; n++) {
		VERBOSE("ANSWER RR %zd\n", n);
		status = wreck_parse_message_rr(op, eop, p, &rrlen);
		if (status != wreck_success) {
			free(r->question.rrname.data);
			WRECK_ERROR(wreck_err_parse_error);
		}
		p += rrlen;
	}
	VERBOSE("\n");

	for (n = 0; n < nscount; n++) {
		VERBOSE("AUTHORITY RR %zd\n", n);
		status = wreck_parse_message_rr(op, eop, p, &rrlen);
		if (status != wreck_success) {
			free(r->question.rrname.data);
			WRECK_ERROR(wreck_err_parse_error);
		}
		p += rrlen;
	}
	VERBOSE("\n");

	for (n = 0; n < arcount; n++) {
		VERBOSE("ADDITIONAL RR %zd\n", n);
		status = wreck_parse_message_rr(op, eop, p, &rrlen);
		if (status != wreck_success) {
			free(r->question.rrname.data);
			WRECK_ERROR(wreck_err_parse_error);
		}
		p += rrlen;
	}
	VERBOSE("\n");

	return (wreck_success);
}
