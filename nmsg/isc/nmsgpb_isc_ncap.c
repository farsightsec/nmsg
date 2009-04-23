/* nmsgpb_isc_ncap.c - ncap protobuf nmsg module */

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

#include "nmsgpb_isc_ncap.h"
#include "ncap.pb-c.c"

#include "dump_dns.h"

/* Exported via module context. */

static nmsg_res ncap_init(void **clos);
static nmsg_res ncap_fini(void **clos);
static nmsg_res ncap_pbuf_inet_ntop(ProtobufCBinaryData *bdata, char *str);
static nmsg_res ncap_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres,
				  const char *el);

static nmsg_res
ncap_print_udp(nmsg_strbuf_t, const char *srcip, const char *dstip,
	       uint16_t srcport, uint16_t dstport,
	       const u_char *payload, size_t paylen, const char *el);

static nmsg_res
ncap_ipdg_to_pbuf(void *clos, const struct nmsg_ipdg *dg,
		  uint8_t **pbuf, size_t *sz);

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.pbdescr = &nmsg__isc__ncap__descriptor,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { MSGTYPE_NCAP_ID, MSGTYPE_NCAP_NAME },
	.init = ncap_init,
	.fini = ncap_fini,
	.pbuf_to_pres = ncap_pbuf_to_pres,
	.ipdg_to_pbuf = ncap_ipdg_to_pbuf
};

/* Private. */

static nmsg_res
ncap_init(void **clos __attribute__((unused))) {
	return (nmsg_res_success);
}

static nmsg_res
ncap_fini(void **clos __attribute__((unused))) {
	return (nmsg_res_success);
}

static nmsg_res
ncap_pbuf_inet_ntop(ProtobufCBinaryData *bdata, char *str) {
	socklen_t strsz = INET6_ADDRSTRLEN;

	if (bdata->len == 4) {
		if (inet_ntop(AF_INET, bdata->data, str, strsz) == NULL)
			return (nmsg_res_failure);
	} else if (bdata->len == 16) {
		if (inet_ntop(AF_INET6, bdata->data, str, strsz) == NULL)
			return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
ncap_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Ncap *nc;
	bool legacy;
	char dstip[INET6_ADDRSTRLEN];
	char srcip[INET6_ADDRSTRLEN];
	const struct ip *ip;
	const struct ip6_hdr *ip6;
	const struct udphdr *udp;
	nmsg_res res;
	struct nmsg_ipdg dg;
	struct nmsg_strbuf sbuf;
	unsigned etype;

	legacy = false;
	dstip[0] = '\0';
	srcip[0] = '\0';
	memset(&sbuf, 0, sizeof(sbuf));

	/* unpack wire format ncap to in-memory struct */
	nc = nmsg__isc__ncap__unpack(NULL, np->payload.len, np->payload.data);
	if (nc == NULL)
		return (nmsg_res_memfail);

	/* parse header fields */
	switch (nc->type) {
	case NMSG__ISC__NCAP_TYPE__IPV4:
		etype = ETHERTYPE_IP;
		nmsg_ipdg_parse(&dg, etype, nc->payload.len, nc->payload.data);
		ip = (const struct ip *) dg.network;
		inet_ntop(AF_INET, &ip->ip_src.s_addr, srcip, sizeof(srcip));
		inet_ntop(AF_INET, &ip->ip_dst.s_addr, dstip, sizeof(dstip));
		break;
	case NMSG__ISC__NCAP_TYPE__IPV6:
		etype = ETHERTYPE_IPV6;
		nmsg_ipdg_parse(&dg, etype, nc->payload.len, nc->payload.data);
		ip6 = (const struct ip6_hdr *) dg.network;
		inet_ntop(AF_INET6, ip6->ip6_src.s6_addr, srcip, sizeof(srcip));
		inet_ntop(AF_INET6, ip6->ip6_dst.s6_addr, dstip, sizeof(dstip));
		break;
	case NMSG__ISC__NCAP_TYPE__Legacy:
		legacy = true;
		if (nc->has_srcip == 0 || nc->has_dstip == 0) {
			nmsg_asprintf(pres, "legacy ncap missing srcip or"
				      " dstip field%s", el);
			goto err;
		}
		if (ncap_pbuf_inet_ntop(&nc->srcip, srcip) == nmsg_res_failure)
		{
			nmsg_asprintf(pres, "unable to decode legacy ncap srcip"
				      " field%s", el);
			goto err;
		}
		if (ncap_pbuf_inet_ntop(&nc->dstip, dstip) == nmsg_res_failure)
		{
			nmsg_asprintf(pres, "unable to decode legacy ncap dstip"
				      " field%s", el);
			goto err;
		}
		break;
	default:
		nmsg_asprintf(pres, "unknown ncap type %u%s", nc->type, el);
		goto err;
		break;
	}

	/* parse payload */
	if (legacy == false) {
		switch (dg.proto_transport) {
		case IPPROTO_UDP:
			udp = (const struct udphdr *) dg.transport;
			res = ncap_print_udp(&sbuf, srcip, dstip,
					     ntohs(udp->uh_sport),
					     ntohs(udp->uh_dport),
					     dg.payload, dg.len_payload, el);
			if (res != nmsg_res_success)
				goto err;
			break;
		default:
			break;
		}
	} else {
		switch (nc->ltype) {
		case NMSG__ISC__NCAP_LEGACY_TYPE__UDP:
			if (nc->has_lint0 == 0 || nc->has_lint1 == 0) {
				nmsg_asprintf(pres, "legacy ncap missing"
					      " srcport or dstport field%s",
					      el);
				goto err;
			}
			res = ncap_print_udp(&sbuf, srcip, dstip,
					     nc->lint0, nc->lint1,
					     nc->payload.data,
					     nc->payload.len, el);
			if (res != nmsg_res_success)
				goto err;
			break;
		case NMSG__ISC__NCAP_LEGACY_TYPE__TCP:
		case NMSG__ISC__NCAP_LEGACY_TYPE__ICMP:
			nmsg_asprintf(pres, "unhandled legacy ncap type %u%s",
				      nc->ltype, el);
			goto err;
			break;
		}
	}

	/* export presentation formatted ncap to caller */
	*pres = sbuf.data;

err:
	/* free unneeded in-memory ncap representation */
	nmsg__isc__ncap__free_unpacked(nc, NULL);

	return (nmsg_res_success);
}

static nmsg_res
ncap_print_udp(nmsg_strbuf_t sb, const char *srcip, const char *dstip,
	       uint16_t srcport, uint16_t dstport,
	       const u_char *payload, size_t paylen, const char *el)
{
	nmsg_res res;

	assert(payload != NULL);
	res = nmsg_strbuf_append(sb, "[%s].%hu [%s].%hu udp [%u]%s",
				 srcip, srcport, dstip, dstport, paylen, el);
	if (res != nmsg_res_success)
		return (nmsg_res_failure);

	if (srcport == 53 || srcport == 5353 ||
	    dstport == 53 || dstport == 5353)
	{
		res = dump_dns(sb, payload, paylen, el);
		assert(res == nmsg_res_success);
	}
	if (res != nmsg_res_success)
		return (nmsg_res_failure);
	nmsg_strbuf_append(sb, "\n");

	return (nmsg_res_success);
}

static nmsg_res
ncap_ipdg_to_pbuf(void *clos __attribute__((unused)),
		  const struct nmsg_ipdg *dg,
		  uint8_t **pbuf, size_t *sz)
{
	Nmsg__Isc__Ncap nc;
	size_t estsz;

	/* initialize in-memory ncap message */
	nmsg__isc__ncap__init(&nc);

	/* set type */
	switch (dg->proto_network) {
	case PF_INET:
		nc.type = NMSG__ISC__NCAP_TYPE__IPV4;
		break;
	case PF_INET6:
		nc.type = NMSG__ISC__NCAP_TYPE__IPV6;
		break;
	default:
		return (nmsg_res_parse_error);
	}

	/* set payload */
	nc.payload.data = (uint8_t *) dg->network;
	nc.payload.len = dg->len_network;

	/* serialize ncap payload */
	estsz = nc.payload.len + 64 /* ad hoc */;
	*pbuf = malloc(estsz);
	if (*pbuf == NULL)
		return (nmsg_res_memfail);
	*sz = nmsg__isc__ncap__pack(&nc, *pbuf);

	return (nmsg_res_pbuf_ready);
}
