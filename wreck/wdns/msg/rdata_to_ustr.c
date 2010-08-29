#include "private.h"

static size_t
rdata_to_str_string(const uint8_t *src, Ustr **s) {
	size_t len;
	uint8_t oclen;

	oclen = *src++;
	ustr_add_cstr(s, "\"");

	len = oclen;
	while (len--) {
		uint8_t c;

		c = *src++;
		if (c == '"') {
			ustr_add_cstr(s, "\\\"");
		} else if (c >= ' ' && c <= '~') {
			ustr_add_buf(s, &c, 1);
		} else {
			ustr_add_fmt(s, "\\%.3d", c);
		}
	}
	ustr_add_cstr(s, "\" ");

	return (oclen + 1); /* number of bytes consumed from src */
}

void
_wdns_rdata_to_ustr(Ustr **s, const uint8_t *rdata, uint16_t rdlen,
		    uint16_t rrtype, uint16_t rrclass)
{

#define bytes_required(n) do { \
	if (src_bytes < ((signed) (n))) \
		goto err; \
} while(0)

#define bytes_consumed(n) do { \
	src += n; \
	src_bytes -= n; \
} while(0)

	char domain_name[WDNS_PRESLEN_NAME];
	const record_descr *descr;
	const uint8_t *src;
	size_t len;
	ssize_t src_bytes;
	uint8_t oclen;
	wdns_msg_status status;
	
	if (rrtype < record_descr_len)
		descr = &record_descr_array[rrtype];

	if (rrtype >= record_descr_len || descr->types[0] == rdf_unknown) {
		/* generic encoding */

		ustr_add_cstr(s, "\\# ");
		ustr_add_fmt(s, "%u ", rdlen);

		for (unsigned i = 0; i < rdlen; i++)
			ustr_add_fmt(s, "%02x ", rdata[i]);

		return;

	} else if (!(descr->record_class == class_un ||
		     descr->record_class == rrclass))
	{
		return;
	}

	src = rdata;
	src_bytes = (ssize_t) rdlen;

	for (const uint8_t *t = &descr->types[0]; *t != rdf_end; t++) {
		if (src_bytes == 0)
			break;

		switch (*t) {
		case rdf_name:
		case rdf_uname:
			status = wdns_len_uname(src, src + src_bytes, &len);
			if (status != wdns_msg_success) {
				src_bytes = 0;
				goto err_status;
			}
			wdns_domain_to_str(src, len, domain_name);
			ustr_add_cstr(s, domain_name);
			ustr_add_cstr(s, " ");
			bytes_consumed(len);
			break;

		case rdf_bytes:
			len = src_bytes;
			while (len > 0) {
				ustr_add_fmt(s, "%02X", *src);
				src++;
				len--;
			}
			src_bytes = 0;
			break;

		case rdf_bytes_b64: {
			base64_encodestate b64;
			char *buf;
			base64_init_encodestate(&b64);
			buf = alloca(2 * src_bytes + 1);
			len = base64_encode_block((const char *) src, src_bytes, buf, &b64);
			ustr_add_buf(s, buf, len);
			len = base64_encode_blockend(buf, &b64);
			ustr_add_buf(s, buf, len);
			src_bytes = 0;
			break;
		}

		case rdf_ipv6prefix:
			bytes_required(1);
			len = oclen = *src++;
			bytes_required(1 + oclen);
			while (len > 0) {
				ustr_add_fmt(s, "%02x", *src);
				src++;
				len--;
			}
			ustr_add_cstr(s, " ");
			src_bytes -= oclen + 1;
			break;

		case rdf_salt:
			bytes_required(1);
			len = oclen = *src++;
			bytes_required(1 + oclen);
			if (oclen == 0)
				ustr_add_cstr(s, "-");
			while (len > 0) {
				ustr_add_fmt(s, "%02x", *src);
				src++;
				len--;
			}
			ustr_add_cstr(s, " ");
			src_bytes -= oclen + 1;
			break;

		case rdf_hash: {
			char *buf;
			bytes_required(1);
			oclen = *src++;
			bytes_required(1 + oclen);
			buf = alloca(2 * oclen + 1);
			len = base32_encode(buf, 2 * oclen + 1, src, oclen);
			ustr_add_buf(s, buf, len);
			ustr_add_cstr(s, " ");
			src += oclen;
			src_bytes -= oclen + 1;
			break;
		}

		case rdf_int8: {
			uint8_t val;
			bytes_required(1);
			memcpy(&val, src, sizeof(val));
			ustr_add_fmt(s, "%u ", val);
			bytes_consumed(1);
			break;
		}

		case rdf_int16: {
			uint16_t val;
			bytes_required(2);
			memcpy(&val, src, sizeof(val));
			val = ntohs(val);
			ustr_add_fmt(s, "%hu ", val);
			bytes_consumed(2);
			break;
		}

		case rdf_int32: {
			uint32_t val;
			bytes_required(4);
			memcpy(&val, src, sizeof(val));
			val = ntohl(val);
			ustr_add_fmt(s, "%u ", val);
			bytes_consumed(4);
			break;
		}

		case rdf_ipv4: {
			char pres[WDNS_PRESLEN_TYPE_A];
			bytes_required(4);
			inet_ntop(AF_INET, src, pres, sizeof(pres));
			ustr_add_cstr(s, pres);
			ustr_add_cstr(s, " ");
			bytes_consumed(4);
			break;
		}

		case rdf_ipv6: {
			char pres[WDNS_PRESLEN_TYPE_AAAA];
			bytes_required(16);
			inet_ntop(AF_INET6, src, pres, sizeof(pres));
			ustr_add_cstr(s, pres);
			ustr_add_cstr(s, " ");
			bytes_consumed(16);
			break;
		}

		case rdf_string: {
			bytes_required(1);
			oclen = *src;
			bytes_required(1 + oclen);
			len = rdata_to_str_string(src, s);
			bytes_consumed(len);
			break;
		}

		case rdf_repstring:
			while (src_bytes > 0) {
				bytes_required(1);
				oclen = *src;
				bytes_required(1 + oclen);
				len = rdata_to_str_string(src, s);
				bytes_consumed(len);
			}
			break;

		case rdf_rrtype: {
			const char *s_rrtype;
			uint16_t my_rrtype;

			bytes_required(2);
			memcpy(&my_rrtype, src, 2);
			my_rrtype = ntohs(my_rrtype);
			bytes_consumed(2);

			s_rrtype = wdns_rrtype_to_str(my_rrtype);
			if (s_rrtype != NULL) {
				ustr_add_cstr(s, s_rrtype);
				ustr_add_cstr(s, " ");
			} else {
				ustr_add_fmt(s, "TYPE%hu ", my_rrtype);
			}

			break;
		}

		case rdf_type_bitmap: {
			const char *s_rrtype;
			uint16_t my_rrtype, lo;
			uint8_t a, b, window_block, bitmap_len;

			bytes_required(2);
			while (src_bytes >= 2) {
				window_block = *src;
				bitmap_len = *(src + 1);
				bytes_consumed(2);
				bytes_required(bitmap_len);
				lo = 0;
				for (int i = 0; i < bitmap_len; i++) {
					a = src[i];
					for (int j = 1; j <= 8; j++) {
						b = a & (1 << (8 - j));
						if (b != 0) {
							my_rrtype = (window_block << 16) | lo;
							s_rrtype = wdns_rrtype_to_str(my_rrtype);
							if (s_rrtype != NULL) {
								ustr_add_cstr(s, s_rrtype);
								ustr_add_cstr(s, " ");
							} else {
								ustr_add_fmt(s, "TYPE%hu ", my_rrtype);
							}
						}
						lo += 1;
					}
				}
				bytes_consumed(bitmap_len);
			}
			break;
		} /* end case */

		}
	}

	/* truncate trailing " " */
	if (ustr_cstr(*s)[ustr_len(*s) - 1] == ' ')
		ustr_del(s, 1);
	
	return;

err:
	ustr_add_fmt(s, " ### PARSE ERROR ###");
	return;

err_status:
	ustr_add_fmt(s, " ### PARSE ERROR #%u ###", status);
	return;
}
