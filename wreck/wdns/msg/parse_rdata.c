#include "private.h"

/**
 * Parse the rdata component of a resource record.
 *
 * \param[in] p pointer to start of message
 * \param[in] eop end of message buffer
 * \param[in] ordata pointer to rdata
 * \param[in] rrtype
 * \param[in] rrclass
 * \param[in] rdlen
 * \param[out] alloc_bytes number of bytes that the parsed rdata will occupy (may be NULL)
 * \param[out] dst destination buffer (may be NULL)
 */

wdns_msg_status
wdns_parse_rdata(const uint8_t *p, const uint8_t *eop, const uint8_t *ordata,
		 uint16_t rrtype, uint16_t rrclass, uint16_t rdlen,
		 size_t *alloc_bytes, uint8_t *dst)
{

#define copy_bytes(x) do { \
	if (bytes_remaining < (x)) \
		WDNS_ERROR(wdns_msg_err_parse_error); \
	if (alloc_bytes) \
		*alloc_bytes += (x); \
	if (dst) { \
		memcpy(dst, rdata, (x)); \
		dst += (x); \
	} \
	rdata += (x); \
	bytes_remaining -= (x); \
} while(0)

	const record_descr *descr;
	const uint8_t *rdata = ordata;
	const uint8_t *t;
	size_t bytes_remaining = rdlen;
	size_t len;
	uint8_t domain_name[255];
	uint8_t oclen;
	wdns_msg_status status;

	if (rrtype < record_descr_len)
		descr = &record_descr_array[rrtype];

	if (rrtype >= record_descr_len || descr->types[0] == rdf_unknown) {
		copy_bytes(bytes_remaining);
		return (wdns_msg_success);
	}

	if (descr->record_class == class_un ||
	    descr->record_class == rrclass)
	{
		for (t = &descr->types[0]; *t != rdf_end; t++) {
			if (bytes_remaining == 0)
				break;

			switch (*t) {
			case rdf_name:
				VERBOSE("parsing name, %zd bytes left\n", bytes_remaining);

				status = wdns_unpack_name(p, eop, rdata, domain_name, &len);
				if (status != wdns_msg_success)
					WDNS_ERROR(wdns_msg_err_parse_error);
				bytes_remaining -= wdns_skip_name(&rdata, eop);

				if (alloc_bytes)
					*alloc_bytes += len;
				if (dst) {
					memcpy(dst, domain_name, len);
					dst += len;
				}
				break;

			case rdf_uname:
				VERBOSE("parsing uname, %zd bytes left\n", bytes_remaining);

				status = wdns_copy_uname(p, eop, rdata, domain_name, &len);
				if (status != wdns_msg_success)
					WDNS_ERROR(wdns_msg_err_parse_error);
				bytes_remaining -= len;

				if (alloc_bytes)
					*alloc_bytes += len;
				if (dst) {
					memcpy(dst, domain_name, len);
					dst += len;
				}
				break;

			case rdf_bytes:
				VERBOSE("parsing byte array, %zd bytes left\n", bytes_remaining);
				copy_bytes(bytes_remaining);
				break;

			case rdf_int8:
				VERBOSE("parsing int8, %zd bytes left\n", bytes_remaining);
				copy_bytes(1U);
				break;

			case rdf_int16:
				VERBOSE("parsing int16, %zd bytes left\n", bytes_remaining);
				copy_bytes(2U);
				break;

			case rdf_int32:
			case rdf_ipv4:
				VERBOSE("parsing int32, %zd bytes left\n", bytes_remaining);
				copy_bytes(4U);
				break;

			case rdf_ipv6:
				VERBOSE("parsing ipv6, %zd bytes left\n", bytes_remaining);
				copy_bytes(16U);
				break;

			case rdf_string:
				VERBOSE("parsing string, %zd bytes left\n", bytes_remaining);
				oclen = *rdata;
				copy_bytes(oclen + 1U);
				break;

			case rdf_repstring:
				VERBOSE("parsing repstring, %zd bytes left\n", bytes_remaining);
				while (bytes_remaining > 0) {
					oclen = *rdata;
					copy_bytes(oclen + 1U);
				}
				break;

			case rdf_ipv6prefix:
				VERBOSE("parsing ipv6prefix, %zd bytes left\n", bytes_remaining);
				oclen = *rdata;
				if (oclen > 16U)
					WDNS_ERROR(wdns_msg_err_parse_error);
				copy_bytes(oclen + 1U);
				break;

			default:
				VERBOSE("ERROR: unhandled rdf type %u\n", *t);
				abort();
			}

		}
		if (bytes_remaining != 0) {
			VERBOSE("ERROR: bytes_remaining=%zd after parsing rdata\n",
				bytes_remaining);
			WDNS_ERROR(wdns_msg_err_parse_error);
		}
	} else {
		VERBOSE("generic copy, %zd bytes left\n", bytes_remaining);
		copy_bytes(bytes_remaining);
	}

	return (wdns_msg_success);
}
