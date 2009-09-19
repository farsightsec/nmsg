#include "private.h"

char *
wdns_rdata_to_str(wdns_dns_rdata_t *rdata, uint16_t rrtype, uint16_t rrclass)
{
	char *p, *pres;
	wdns_dns_name_t name;
	size_t len;
	uint8_t *data;

	if (rrclass == WDNS_CLASS_IN) {
		switch (rrtype) {
		case WDNS_TYPE_SOA:
			p = pres = malloc(rdata->len + 60);
			if (pres == NULL)
				return (NULL);
			data = rdata->data;

			len = wdns_domain_to_str(data, p);
			VERBOSE("domain_to_pres len=%zd\n", len);
			data += len + 1;
			p += len;

			*p++ = ',';

			len = wdns_domain_to_str(data, p);
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
		case WDNS_TYPE_A:
			pres = malloc(WDNS_PRESLEN_TYPE_A);
			if (pres == NULL)
				return (NULL);
			inet_ntop(AF_INET, rdata->data, pres, WDNS_PRESLEN_TYPE_A);
			return (pres);
		case WDNS_TYPE_AAAA:
			pres = malloc(WDNS_PRESLEN_TYPE_AAAA);
			if (pres == NULL)
				return (NULL);
			inet_ntop(AF_INET6, rdata->data, pres, WDNS_PRESLEN_TYPE_AAAA);
			return (pres);
		case WDNS_TYPE_NS:
		case WDNS_TYPE_CNAME:
		case WDNS_TYPE_PTR:
			name.len = rdata->len;
			name.data = rdata->data;
			return (wdns_name_to_str(&name));
		}
	}

	return (NULL);
}
