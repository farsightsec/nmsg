#include "private.h"

wdns_msg_status
wdns_rdata_to_str(const wdns_rdata_t *rdata, uint16_t rrtype, uint16_t rrclass,
		  char *dst, size_t *dstsz)
{
	char domain_name[WDNS_PRESLEN_NAME];
	const record_descr *descr;
	const uint8_t *src;
	int rc;
	size_t len;
	size_t src_bytes = rdata->len;
	uint8_t oclen;

	if (rrtype < record_descr_len)
		descr = &record_descr_array[rrtype];

	if (rrtype >= record_descr_len || descr->types[0] == rdf_unknown) {
		/* generic encoding */

		const char generic[] = "\\# ";

		len = sizeof(generic) + sizeof("65535 ") + rdata->len * (sizeof("FF ") - 1);

		if (dstsz)
			*dstsz = len;

		if (dst) {
			strncpy(dst, generic, sizeof(generic));
			dst += sizeof(generic) - 1;
			len -= sizeof(generic) - 1;

			rc = snprintf(dst, len, "%u ", rdata->len);
			if (rc < 0)
				WDNS_ERROR(wdns_msg_err_parse_error);
			dst += rc;
			len -= rc;

			for (unsigned i = 0; i < rdata->len; i++) {
				rc = snprintf(dst, len, "%02x ", rdata->data[i]);
				if (rc < 0)
					WDNS_ERROR(wdns_msg_err_parse_error);
				dst += rc;
				len -= rc;
			}
		}
		return (wdns_msg_success);
	}

	if (descr->record_class == class_un ||
	    descr->record_class == rrclass)
	{
		const uint8_t *t;

		src = rdata->data;
		if (dstsz)
			*dstsz = 0;

		for (t = &descr->types[0]; *t != rdf_end; t++) {
			if (src_bytes == 0)
				break;

			switch (*t) {
			case rdf_name:
			case rdf_uname:
				len = wdns_domain_to_str(src, domain_name);
				if (dstsz)
					*dstsz += len + 1;
				if (dst) {
					strncpy(dst, domain_name, len);
					dst += strlen(domain_name);
					*dst++ = ' ';
				}
				src += len;
				src_bytes -= len - 1;
				break;

			case rdf_bytes:
				if (dstsz)
					*dstsz += src_bytes * 2 + 1;
				if (dst) {
					len = src_bytes;
					while (len > 0) {
						rc = snprintf(dst, len, "%02x", *src);
						if (rc < 0)
							WDNS_ERROR(wdns_msg_err_parse_error);
						dst += rc;
						src++;
						len--;
					}
					*dst++ = ' ';
				}
				src_bytes = 0;
				break;

			case rdf_ipv6prefix:
				oclen = *src++;
				if (dstsz)
					*dstsz += oclen * 2 + 1;
				while (oclen > 0) {
					if (dst) {
						rc = snprintf(dst, oclen, "%02x", *src);
						if (rc < 0)
							WDNS_ERROR(wdns_msg_err_parse_error);
						dst += rc;
					}
					src++;
					oclen--;
				}
				if (dst)
					*dst++ = ' ';
				src_bytes -= oclen + 1;
				break;

			case rdf_int8:
				if (dstsz)
					*dstsz += sizeof("255");
				if (dst) {
					uint8_t val;
					memcpy(&val, src, sizeof(val));

					rc = snprintf(dst, src_bytes, "%u", val);
					if (rc < 0)
						WDNS_ERROR(wdns_msg_err_parse_error);
					dst += rc;
					*dst++ = ' ';
				}
				src += 1;
				src_bytes -= 1;
				break;

			case rdf_int16:
				if (dstsz)
					*dstsz += sizeof("65535");
				if (dst) {
					uint16_t val;
					memcpy(&val, src, sizeof(val));
					val = ntohs(val);

					rc = snprintf(dst, src_bytes, "%u", val);
					if (rc < 0)
						WDNS_ERROR(wdns_msg_err_parse_error);
					dst += rc;
					*dst++ = ' ';
				}
				src += 2;
				src_bytes -= 2;
				break;

			case rdf_int32:
				if (dstsz)
					*dstsz += sizeof("4294967295");
				if (dst) {
					uint32_t val;
					memcpy(&val, src, sizeof(val));
					val = ntohl(val);

					rc = snprintf(dst, src_bytes, "%u", val);
					if (rc < 0)
						WDNS_ERROR(wdns_msg_err_parse_error);
					dst += rc;
					*dst++ = ' ';
				}
				src += 4;
				src_bytes -= 4;
				break;

			case rdf_ipv4:
				if (dstsz)
					*dstsz += WDNS_PRESLEN_TYPE_A + 1;
				if (dst) {
					char pres[WDNS_PRESLEN_TYPE_A];
					inet_ntop(AF_INET, src, pres, sizeof(pres));
					strncpy(dst, pres, sizeof(pres));
					dst += strlen(pres);
					*dst++ = ' ';
				}
				src += 4;
				src_bytes -= 4;
				break;

			case rdf_ipv6:
				if (dstsz)
					*dstsz += WDNS_PRESLEN_TYPE_AAAA + 1;
				if (dst) {
					char pres[WDNS_PRESLEN_TYPE_AAAA];
					inet_ntop(AF_INET6, src, pres, sizeof(pres));
					strncpy(dst, pres, sizeof(pres));
					dst += strlen(pres);
					*dst++ = ' ';
				}
				src += 16;
				src_bytes -= 16;
				break;

			case rdf_string:
				oclen = *src++;
				if (dstsz)
					*dstsz += oclen + 1;
				if (dst) {
					/* XXX do this properly */
					memcpy(dst, src, oclen);
					dst += oclen;
					*dst++ = ' ';
				}
				src += oclen;
				src_bytes -= oclen + 1;
				break;

			case rdf_repstring:
				while (src_bytes > 0) {
					oclen = *src++;
					if (dstsz)
						*dstsz += oclen + 1;
					if (dst) {
						/* XXX do this properly */
						memcpy(dst, src, oclen);
						dst += oclen;
						*dst++ = ' ';
					}
					src += oclen;
					src_bytes -= oclen + 1;
				}
				break;

			default:
				VERBOSE("ERROR: unhandled rdf type %u\n", *t);
				abort();
			}
		}

		if (dstsz)
			*dstsz += 1; /* terminal \0 */
		if (dst) {
			*dst = '\0';
			if (*(dst - 1) == ' ')
				*(dst - 1) = '\0';
		}

		return (wdns_msg_success);
	} else {
		return (wdns_msg_err_parse_error);
	}
}
