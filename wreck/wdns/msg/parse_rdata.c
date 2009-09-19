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
	const uint8_t *rdata = ordata;
	size_t len, bytes_read = 0;
	uint8_t domain_name[255];
	uint8_t oclen;
	wdns_msg_status status;

	if (rrclass == WDNS_CLASS_IN) {
		switch (rrtype) {
		case WDNS_TYPE_SOA:
			/* MNAME and RNAME */
			for (int i = 0; i < 2; i++) {
				status = wdns_name_unpack(p, eop, rdata, domain_name, &len);
				if (status != wdns_msg_success)
					WDNS_ERROR(wdns_msg_err_parse_error);
				bytes_read += wdns_name_skip(&rdata, eop);

				if (alloc_bytes)
					*alloc_bytes += len;
				if (dst) {
					memcpy(dst, domain_name, len);
					dst += len;
				}
			}

			/* five 32 bit integers: 5*4 = 20 bytes
			 * SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM */
			if (eop - rdata < 20)
				WDNS_ERROR(wdns_msg_err_parse_error);

			if (alloc_bytes)
				*alloc_bytes += 20;
			if (dst)
				memcpy(dst, rdata, 20);
			rdata += 20;
			bytes_read += 20;

			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN/SOA rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WDNS_ERROR(wdns_msg_err_parse_error);
			}
			break;

		case WDNS_TYPE_MX:
		case WDNS_TYPE_RT:
			/* 16 bit integer */
			if (alloc_bytes)
				*alloc_bytes += 2;
			if (dst) {
				memcpy(dst, rdata, 2);
				dst += 2;
			}
			rdata += 2;
			bytes_read += 2;

			/* domain name */
			status = wdns_name_unpack(p, eop, rdata, domain_name, &len);
			if (status != wdns_msg_success)
				WDNS_ERROR(wdns_msg_err_parse_error);
			bytes_read += wdns_name_skip(&rdata, eop);
			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN/MX rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WDNS_ERROR(wdns_msg_err_parse_error);
			}

			if (alloc_bytes)
				*alloc_bytes += len;
			if (dst)
				memcpy(dst, domain_name, len);

			break;

		case WDNS_TYPE_A:
			if (rdlen == 4) {
				if (alloc_bytes)
					*alloc_bytes = rdlen;
				if (dst)
					memcpy(dst, rdata, rdlen);
				rdata += rdlen;
			} else {
				VERBOSE("ERROR: IN/A rdlen=%u, should be 4\n", rdlen);
				WDNS_ERROR(wdns_msg_err_parse_error);
			}
			break;

		case WDNS_TYPE_AAAA:
			if (rdlen == 16) {
				if (alloc_bytes)
					*alloc_bytes = rdlen;
				if (dst)
					memcpy(dst, rdata, rdlen);
				rdata += rdlen;
			} else {
				VERBOSE("ERROR: IN/AAAA rdlen=%u, should be 16\n", rdlen);
				WDNS_ERROR(wdns_msg_err_parse_error);
			}
			break;

		case WDNS_TYPE_NS:
		case WDNS_TYPE_CNAME:
		case WDNS_TYPE_PTR:
		case WDNS_TYPE_MB:
		case WDNS_TYPE_MD:
		case WDNS_TYPE_MF:
		case WDNS_TYPE_MG:
		case WDNS_TYPE_MR:
			/* these rdata types have a single domain name */
			if (rdlen == 0) {
				VERBOSE("ERROR: IN name rdata but no name\n");
				WDNS_ERROR(wdns_msg_err_parse_error);
			}

			status = wdns_name_unpack(p, eop, rdata, domain_name, &len);
			if (status != wdns_msg_success) {
				VERBOSE("ERROR: IN name rdata contained invalid name\n");
				WDNS_ERROR(wdns_msg_err_parse_error);
			}
			if (alloc_bytes)
				*alloc_bytes = len;
			if (dst)
				memcpy(dst, domain_name, len);

			bytes_read = wdns_name_skip(&rdata, eop);
			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN name rdata rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WDNS_ERROR(wdns_msg_err_parse_error);
			}
			break;

		case WDNS_TYPE_MINFO:
		case WDNS_TYPE_RP:
			/* these rdata types have two domain names */
			/* technically RP should not be compressed (RFC 3597) */
			for (int i = 0; i < 2; i++) {
				status = wdns_name_unpack(p, eop, rdata, domain_name, &len);
				if (status != wdns_msg_success) {
					VERBOSE("ERROR: IN 2name (#%d) rdata contained "
						"invalid name\n", i);
					WDNS_ERROR(wdns_msg_err_parse_error);
				}
				if (alloc_bytes)
					*alloc_bytes += len;
				if (dst)
					memcpy(dst, domain_name, len);

				bytes_read += wdns_name_skip(&rdata, eop);
			}
			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN 2name rdata rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WDNS_ERROR(wdns_msg_err_parse_error);
			}
			break;

		case WDNS_TYPE_TXT:
			len = rdlen;
			while (len-- && rdata <= ordata + rdlen) {
				oclen = *rdata++;
				if (rdata + oclen > ordata + rdlen) {
					VERBOSE("ERROR: IN/TXT rdata overflow\n");
					WDNS_ERROR(wdns_msg_err_parse_error);
				}
				WDNS_BUF_ADVANCE(rdata, len, oclen);
			}
			if (rdata == ordata + rdlen) {
				rdata = ordata;
				if (alloc_bytes)
					*alloc_bytes = rdlen;
				if (dst)
					memcpy(dst, rdata, rdlen);
			}
			break;
		default:
			if (alloc_bytes)
				*alloc_bytes = rdlen;
			if (dst)
				memcpy(dst, rdata, rdlen);
			return (wdns_msg_success);
			break;
		}
	} else {
		if (alloc_bytes)
			*alloc_bytes = rdlen;
		if (dst)
			memcpy(dst, rdata, rdlen);
	}

	return (wdns_msg_success);
}
