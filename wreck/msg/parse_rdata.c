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
	size_t len;
	uint8_t domain_name[255];
	wreck_status status;

	if (rrclass == WRECK_DNS_CLASS_IN || rrtype == WRECK_DNS_TYPE_OPT) {
		switch (rrtype) {
		case WRECK_DNS_TYPE_SOA:
			/* MNAME and RNAME */
			for (int i = 0; i < 2; i++) {
				status = wreck_name_unpack(p, eop, rdata, domain_name, &len);
				if (status != wreck_success)
					WRECK_ERROR(wreck_err_parse_error);
				wreck_name_skip(&rdata, eop);

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

			break;

		case WRECK_DNS_TYPE_A:
			if (rdlen == 4) {
				if (alloc_bytes)
					*alloc_bytes = rdlen;
				if (dst)
					memcpy(dst, rdata, rdlen);
				rdata += rdlen;
			}
			break;

		case WRECK_DNS_TYPE_AAAA:
			if (rdlen == 16) {
				if (alloc_bytes)
					*alloc_bytes = rdlen;
				if (dst)
					memcpy(dst, rdata, rdlen);
				rdata += rdlen;
			}
			break;

		case WRECK_DNS_TYPE_NS:
		case WRECK_DNS_TYPE_CNAME:
		case WRECK_DNS_TYPE_PTR:
			status = wreck_name_unpack(p, eop, rdata, domain_name, &len);
			if (status != wreck_success)
				WRECK_ERROR(wreck_err_parse_error);
			if (alloc_bytes)
				*alloc_bytes = len;
			if (dst)
				memcpy(dst, domain_name, len);
			wreck_name_skip(&rdata, eop);
			break;

		case WRECK_DNS_TYPE_OPT:
		case WRECK_DNS_TYPE_TXT:
			if (alloc_bytes)
				*alloc_bytes = rdlen;
			if (dst)
				memcpy(dst, rdata, rdlen);
			rdata += rdlen;
			break;
		default:
			VERBOSE("unhandled rdata rrclass=%hu rrtype=%hu\n", rrclass, rrtype);
			if (alloc_bytes)
				*alloc_bytes = rdlen;
			return (wreck_success);
			break;
		}
	}

	if (rdata - ordata != rdlen) {
		VERBOSE("rdlen=%u, expected %ld\n", rdlen, rdata - ordata);
		WRECK_ERROR(wreck_err_parse_error);
	}

	return (wreck_success);
}
