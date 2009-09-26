/* nmsgpb_isc_dns.c - dns protobuf nmsg module */

/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include "nmsg_port.h"
#include "nmsg_port_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <wdns.h>

#include "nmsgpb_isc_dns.h"
#include "dns.pb-c.c"

/* Exported via module context. */

static nmsg_res dns_init(void **clos);
static nmsg_res dns_fini(void **clos);
static nmsg_res dns_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres,
				 const char *el);

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.pbdescr = &nmsg__isc__dns__descriptor,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { MSGTYPE_DNS_ID, MSGTYPE_DNS_NAME },

	.init = dns_init,
	.fini = dns_fini,
	.pbuf_to_pres = dns_pbuf_to_pres
};

/* Private. */

static nmsg_res
dns_init(void **clos __attribute__((unused))) {
	return (nmsg_res_success);
}

static nmsg_res
dns_fini(void **clos __attribute__((unused))) {
	return (nmsg_res_success);
}

static nmsg_res
dns_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Dns *dns;
	char name[WDNS_MAXLEN_NAME];
	nmsg_res res;
	size_t i;
	struct nmsg_strbuf sbuf;

	memset(&sbuf, 0, sizeof(sbuf));

	/* unpack wire format dns to in-memory struct */
	dns = nmsg__isc__dns__unpack(NULL, np->payload.len, np->payload.data);
	if (dns == NULL)
		return (nmsg_res_memfail);

	/* convert to presentation format */
	if (dns->rrname.len > WDNS_MAXLEN_NAME)
		goto err;

	if (dns->has_rrname) {
		wdns_domain_to_str(dns->rrname.data, name);
		res = nmsg_strbuf_append(&sbuf, "rrname: %s%s", name, el);
		if (res != nmsg_res_success)
			goto err;
	}

	if (dns->has_rrtype) {
		res = nmsg_strbuf_append(&sbuf, "rrtype: %u%s",
					 dns->rrtype, el);
		if (res != nmsg_res_success)
			goto err;
	}

	if (dns->has_rrclass) {
		res = nmsg_strbuf_append(&sbuf, "rrclass: %u%s",
					 dns->rrclass, el);
		if (res != nmsg_res_success)
			goto err;
	}

	if (dns->has_rrttl) {
		res = nmsg_strbuf_append(&sbuf, "rrttl: %u%s",
					 dns->rrttl, el);
		if (res != nmsg_res_success)
			goto err;
	}

	for (i = 0; i < dns->n_rdata; i++) {
		const uint8_t *rdata;
		size_t len;

		res = nmsg_strbuf_append(&sbuf, "rdata: ");
		if (res != nmsg_res_success)
			goto err;

		len = dns->rdata[i].len;
		rdata = dns->rdata[i].data;
		while (len-- != 0) {
			res = nmsg_strbuf_append(&sbuf, "%02x", *rdata++);
			if (res != nmsg_res_success)
				goto err;
		}

		res = nmsg_strbuf_append(&sbuf, "%s", el);
		if (res != nmsg_res_success)
			goto err;
	}

	/* export presentation formatted ncap to caller */
	*pres = sbuf.data;

err:
	/* free unneeded in-memory ncap representation */
	nmsg__isc__dns__free_unpacked(dns, NULL);

	return (nmsg_res_success);
}
