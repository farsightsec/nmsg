#include "private.h"

/**
 * Parse a DNS resource record contained in a DNS message.
 *
 * \param[in] p the DNS message that contains the resource record
 * \param[in] eop pointer to end of buffer containing message
 * \param[in] data pointer to start of resource record
 * \param[out] rrsz number of wire bytes read from message (may be NULL)
 * \param[out] rr parsed resource record (may be NULL)
 */

wreck_msg_status
wreck_parse_message_rr(const uint8_t *p, const uint8_t *eop, const uint8_t *data,
		       size_t *rrsz, wreck_dns_rr_t *rr)
{
	const uint8_t *buf = data;
	size_t alloc_bytes = 0;
	size_t len;
	uint16_t rrtype, rrclass, rdlen;
	uint32_t rrttl;
	uint8_t domain_name[255];
	wreck_msg_status status;

	/* uncompress name */
	status = wreck_name_unpack(p, eop, buf, domain_name, &len);
	if (status != wreck_msg_success)
		WRECK_ERROR(wreck_msg_err_parse_error);

	/* copy name */
	if (rr) {
		rr->name.len = len;
		rr->name.data = malloc(len);
		if (rr->name.data == NULL)
			WRECK_ERROR(wreck_msg_err_malloc);
		memcpy(rr->name.data, domain_name, len);
	}

	/* skip name */
	wreck_name_skip(&buf, eop);

	if (buf + 10 > eop) {
		if (rr) {
			free(rr->name.data);
			rr->name.data = NULL;
		}
		WRECK_ERROR(wreck_msg_err_parse_error);
	}

	/* rr type, rr class, rr ttl, rdata length */
	WRECK_BUF_GET16(rrtype, buf);
	WRECK_BUF_GET16(rrclass, buf);
	WRECK_BUF_GET32(rrttl, buf);
	WRECK_BUF_GET16(rdlen, buf);

	/* rdlen overflow check */
	if (buf + rdlen > eop) {
		if (rr) {
			free(rr->name.data);
			rr->name.data = NULL;
		}
		VERBOSE("rdlen overflow buf=%p rdlen=%u eop=%p\n", buf, rdlen, eop);
		WRECK_ERROR(wreck_msg_err_overflow);
	}

#if DEBUG
	wreck_print_rr(stdout, domain_name, rrtype, rrclass, rrttl, rdlen, buf);
#endif

	/* check how large the parsed rdata will be */
	status = wreck_parse_rdata(p, eop, buf, rrtype, rrclass, rdlen, &alloc_bytes, NULL);
	if (status != wreck_msg_success) {
		if (rr) {
			free(rr->name.data);
			rr->name.data = NULL;
		}
		WRECK_ERROR(wreck_msg_err_parse_error);
	}

	/* parse and copy the rdata */
	if (rr) {
		rr->rdata = malloc(sizeof(wreck_dns_rdata_t) + alloc_bytes);
		if (rr->rdata == NULL) {
			free(rr->name.data);
			rr->name.data = NULL;
			WRECK_ERROR(wreck_msg_err_malloc);
		}
		rr->rdata->len = alloc_bytes;
		wreck_parse_rdata(p, eop, buf, rrtype, rrclass, rdlen, NULL, rr->rdata->data);

		rr->rrtype = rrtype;
		rr->rrclass = rrclass;
		rr->rrttl = rrttl;
	}

	if (rrsz)
		*rrsz = (buf - data) + rdlen;

	return (wreck_msg_success);
}
