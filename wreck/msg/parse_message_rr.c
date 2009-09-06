#include "private.h"

/**
 * Parse a DNS resource record contained in a DNS message.
 *
 * \param[in] p the DNS message that contains the resource record
 * \param[in] eop pointer to end of buffer containing message
 * \param[in] rr pointer to start of resource record
 * \param[out] sz number of bytes read from message (may be NULL)
 */

wreck_status
wreck_parse_message_rr(const uint8_t *p, const uint8_t *eop, const uint8_t *rr, size_t *sz)
{
	const uint8_t *buf = rr;
	wreck_dns_name_t name;
	size_t alloc_bytes = 0;
	size_t len;
	uint16_t rrtype, rrclass, rdlen;
	uint32_t rrttl;
	uint8_t domain_name[255];
	wreck_dns_rdata_t *rdata;
	wreck_status status;

	/* uncompress name */
	status = wreck_name_unpack(p, eop, buf, domain_name, &len);
	if (status != wreck_success)
		WRECK_ERROR(wreck_err_parse_error);

	/* copy name */
	name.len = len;
	name.data = malloc(name.len);
	if (name.data == NULL)
		WRECK_ERROR(wreck_err_malloc);
	memcpy(name.data, domain_name, len);

	/* skip name */
	wreck_name_skip(&buf, eop);

	if (buf >= eop) {
		free(name.data);
		WRECK_ERROR(wreck_err_parse_error);
	}

	/* rr type, rr class, rr ttl, rdata length */
	WRECK_BUF_GET16(rrtype, buf);
	WRECK_BUF_GET16(rrclass, buf);
	WRECK_BUF_GET32(rrttl, buf);
	WRECK_BUF_GET16(rdlen, buf);

	if (buf + rdlen > eop) {
		free(name.data);
		WRECK_ERROR(wreck_err_parse_error);
	}

#if DEBUG
	wreck_print_rr(stdout, &name, rrtype, rrclass, rrttl, rdlen, buf);
#endif

	status = wreck_parse_rdata(p, eop, buf, rrtype, rrclass, rdlen, &alloc_bytes, NULL);
	if (status != wreck_success) {
		free(name.data);
		WRECK_ERROR(wreck_err_parse_error);
	}

	rdata = malloc(sizeof(*rdata) + alloc_bytes);
	if (rdata == NULL) {
		free(name.data);
		WRECK_ERROR(wreck_err_malloc);
	}
	rdata->len = alloc_bytes;
	wreck_parse_rdata(p, eop, buf, rrtype, rrclass, rdlen, NULL, rdata->data);

	free(rdata);

	free(name.data);

	if (sz)
		*sz = (buf - rr) + rdlen;

	return (wreck_success);
}
