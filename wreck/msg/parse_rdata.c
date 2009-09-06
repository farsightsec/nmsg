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

wreck_status
wreck_parse_rdata(const uint8_t *p, const uint8_t *eop, const uint8_t *ordata,
		  uint16_t rrtype, uint16_t rrclass, uint16_t rdlen,
		  size_t *alloc_bytes, uint8_t *dst)
{
	const uint8_t *rdata = ordata;
	size_t len, bytes_read = 0;
	uint8_t domain_name[255];
	wreck_status status;

	if (rrclass == WRECK_DNS_CLASS_IN) {
		switch (rrtype) {
		case WRECK_DNS_TYPE_SOA:
			/* MNAME and RNAME */
			for (int i = 0; i < 2; i++) {
				status = wreck_name_unpack(p, eop, rdata, domain_name, &len);
				if (status != wreck_success)
					WRECK_ERROR(wreck_err_parse_error);
				bytes_read += wreck_name_skip(&rdata, eop);

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
				WRECK_ERROR(wreck_err_parse_error);

			if (alloc_bytes)
				*alloc_bytes += 20;
			if (dst)
				memcpy(dst, rdata, 20);
			rdata += 20;
			bytes_read += 20;

			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN/SOA rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WRECK_ERROR(wreck_err_parse_error);
			}
			break;

		case WRECK_DNS_TYPE_MX:
		case WRECK_DNS_TYPE_RT:
			/* 16 bit integer */
			if (alloc_bytes)
				*alloc_bytes += 2;
			if (dst)
				memcpy(dst, rdata, 2);
			rdata += 2;
			bytes_read += 2;

			/* domain name*/
			status = wreck_name_unpack(p, eop, rdata, domain_name, &len);
			if (status != wreck_success)
				WRECK_ERROR(wreck_err_parse_error);
			bytes_read += wreck_name_skip(&rdata, eop);
			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN/MX rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WRECK_ERROR(wreck_err_parse_error);
			}

			if (alloc_bytes)
				*alloc_bytes += len;
			if (dst)
				memcpy(dst, domain_name, len);

			break;

		case WRECK_DNS_TYPE_A:
			if (rdlen == 4) {
				if (alloc_bytes)
					*alloc_bytes = rdlen;
				if (dst)
					memcpy(dst, rdata, rdlen);
				rdata += rdlen;
			} else {
				VERBOSE("ERROR: IN/A rdlen=%u, should be 4\n", rdlen);
				WRECK_ERROR(wreck_err_parse_error);
			}
			break;

		case WRECK_DNS_TYPE_AAAA:
			if (rdlen == 16) {
				if (alloc_bytes)
					*alloc_bytes = rdlen;
				if (dst)
					memcpy(dst, rdata, rdlen);
				rdata += rdlen;
			} else {
				VERBOSE("ERROR: IN/AAAA rdlen=%u, should be 16\n", rdlen);
				WRECK_ERROR(wreck_err_parse_error);
			}
			break;

		case WRECK_DNS_TYPE_NS:
		case WRECK_DNS_TYPE_CNAME:
		case WRECK_DNS_TYPE_PTR:
		case WRECK_DNS_TYPE_MB:
		case WRECK_DNS_TYPE_MD:
		case WRECK_DNS_TYPE_MF:
		case WRECK_DNS_TYPE_MG:
		case WRECK_DNS_TYPE_MR:
			/* these rdata types have a single domain name */
			if (rdlen == 0) {
				VERBOSE("ERROR: IN name rdata but no name\n");
				WRECK_ERROR(wreck_err_parse_error);
			}

			status = wreck_name_unpack(p, eop, rdata, domain_name, &len);
			if (status != wreck_success) {
				VERBOSE("ERROR: IN name rdata contained invalid name\n");
				WRECK_ERROR(wreck_err_parse_error);
			}
			if (alloc_bytes)
				*alloc_bytes = len;
			if (dst)
				memcpy(dst, domain_name, len);

			bytes_read = wreck_name_skip(&rdata, eop);
			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN name rdata rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WRECK_ERROR(wreck_err_parse_error);
			}
			break;

		case WRECK_DNS_TYPE_MINFO:
		case WRECK_DNS_TYPE_RP:
			/* these rdata types have two domain names */
			/* technically RP should not be compressed (RFC 3597) */
			for (int i = 0; i < 2; i++) {
				status = wreck_name_unpack(p, eop, rdata, domain_name, &len);
				if (status != wreck_success) {
					VERBOSE("ERROR: IN 2name (#%d) rdata contained "
						"invalid name\n", i);
					WRECK_ERROR(wreck_err_parse_error);
				}
				if (alloc_bytes)
					*alloc_bytes = len;
				if (dst)
					memcpy(dst, domain_name, len);

				bytes_read += wreck_name_skip(&rdata, eop);
			}
			if (bytes_read != rdlen) {
				VERBOSE("ERROR: IN 2name rdata rdlen=%u but read %zd bytes\n",
					rdlen, bytes_read);
				WRECK_ERROR(wreck_err_parse_error);
			}
			break;

		case WRECK_DNS_TYPE_TXT:
			if (alloc_bytes)
				*alloc_bytes = rdlen;
			if (dst)
				memcpy(dst, rdata, rdlen);
			rdata += rdlen;
			break;
		default:
			if (alloc_bytes)
				*alloc_bytes = rdlen;
			if (dst)
				memcpy(dst, rdata, rdlen);
			return (wreck_success);
			break;
		}
	} else {
		if (alloc_bytes)
			*alloc_bytes = rdlen;
		if (dst)
			memcpy(dst, rdata, rdlen);
	}

	return (wreck_success);
}
