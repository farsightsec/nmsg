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

wdns_msg_status
wdns_parse_message_rr(const uint8_t *p, const uint8_t *eop, const uint8_t *data,
		       size_t *rrsz, wdns_dns_rr_t *rr)
{
	const uint8_t *buf = data;
	size_t alloc_bytes = 0;
	size_t len;
	uint16_t rrtype, rrclass, rdlen;
	uint32_t rrttl;
	uint8_t domain_name[255];
	wdns_msg_status status;

	/* uncompress name */
	status = wdns_name_unpack(p, eop, buf, domain_name, &len);
	if (status != wdns_msg_success)
		WDNS_ERROR(wdns_msg_err_parse_error);

	/* copy name */
	if (rr) {
		rr->name.len = len;
		rr->name.data = malloc(len);
		if (rr->name.data == NULL)
			WDNS_ERROR(wdns_msg_err_malloc);
		memcpy(rr->name.data, domain_name, len);
	}

	/* skip name */
	wdns_name_skip(&buf, eop);

	if (buf + 10 > eop) {
		if (rr) {
			free(rr->name.data);
			rr->name.data = NULL;
		}
		WDNS_ERROR(wdns_msg_err_parse_error);
	}

	/* rr type, rr class, rr ttl, rdata length */
	WDNS_BUF_GET16(rrtype, buf);
	WDNS_BUF_GET16(rrclass, buf);
	WDNS_BUF_GET32(rrttl, buf);
	WDNS_BUF_GET16(rdlen, buf);

	/* rdlen overflow check */
	if (buf + rdlen > eop) {
		if (rr) {
			free(rr->name.data);
			rr->name.data = NULL;
		}
		VERBOSE("rdlen overflow buf=%p rdlen=%u eop=%p\n", buf, rdlen, eop);
		WDNS_ERROR(wdns_msg_err_overflow);
	}

#if DEBUG
	wdns_print_rr(stdout, domain_name, rrtype, rrclass, rrttl, rdlen, buf);
#endif

	/* check how large the parsed rdata will be */
	status = wdns_parse_rdata(p, eop, buf, rrtype, rrclass, rdlen, &alloc_bytes, NULL);
	if (status != wdns_msg_success) {
		if (rr) {
			free(rr->name.data);
			rr->name.data = NULL;
		}
		WDNS_ERROR(wdns_msg_err_parse_error);
	}

	/* parse and copy the rdata */
	if (rr) {
		rr->rdata = malloc(sizeof(wdns_dns_rdata_t) + alloc_bytes);
		if (rr->rdata == NULL) {
			free(rr->name.data);
			rr->name.data = NULL;
			WDNS_ERROR(wdns_msg_err_malloc);
		}
		rr->rdata->len = alloc_bytes;
		wdns_parse_rdata(p, eop, buf, rrtype, rrclass, rdlen, NULL, rr->rdata->data);

		rr->rrtype = rrtype;
		rr->rrclass = rrclass;
		rr->rrttl = rrttl;
	}

	if (rrsz)
		*rrsz = (buf - data) + rdlen;

	return (wdns_msg_success);
}
