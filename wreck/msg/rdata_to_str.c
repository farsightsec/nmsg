#include "private.h"

char *
wreck_rdata_to_str(wreck_dns_rdata_t *rdata, uint16_t rrtype, uint16_t rrclass)
{
	char *p, *pres;
	wreck_dns_name_t name;
	size_t len;
	uint8_t *data;

	if (rrclass == WRECK_DNS_CLASS_IN) {
		switch (rrtype) {
		case WRECK_DNS_TYPE_SOA:
			p = pres = malloc(rdata->len + 60);
			if (pres == NULL)
				return (NULL);
			data = rdata->data;

			len = wreck_domain_to_str(data, p);
			VERBOSE("domain_to_pres len=%zd\n", len);
			data += len + 1;
			p += len;

			*p++ = ',';

			len = wreck_domain_to_str(data, p);
			VERBOSE("domain_to_pres len=%zd\n", len);
			data += len + 1;
			p += len;

			*p++ = ',';

			for (int i = 0; i < 5; i++) {
				uint32_t val;

				memcpy(&val, data, 4);
				data += 4;
				len = sprintf(p, "%d", ntohl(val));
				p += len;
				*p++ = ',';
			}
			*--p = '\0';
			return (pres);
		case WRECK_DNS_TYPE_A:
			pres = malloc(WRECK_DNS_PRESLEN_TYPE_A);
			if (pres == NULL)
				return (NULL);
			inet_ntop(AF_INET, rdata->data, pres, WRECK_DNS_PRESLEN_TYPE_A);
			return (pres);
		case WRECK_DNS_TYPE_AAAA:
			pres = malloc(WRECK_DNS_PRESLEN_TYPE_AAAA);
			if (pres == NULL)
				return (NULL);
			inet_ntop(AF_INET6, rdata->data, pres, WRECK_DNS_PRESLEN_TYPE_AAAA);
			return (pres);
		case WRECK_DNS_TYPE_NS:
		case WRECK_DNS_TYPE_CNAME:
		case WRECK_DNS_TYPE_PTR:
			name.len = rdata->len;
			name.data = rdata->data;
			return (wreck_name_to_str(&name));
		}
	}

	return (NULL);
}
