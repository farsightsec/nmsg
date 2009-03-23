/* pbnmsg_isc_ncap.c - ncap protobuf nmsg module */

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
#include <nmsg/asprintf.h>
#include <nmsg/ipdg.h>
#include <nmsg/pbmod.h>
#include <nmsg/strbuf.h>

#include "pbnmsg_isc_ncap.h"
#include "ncap.pb-c.c"

/* Data structures. */

struct ncap_clos {
	int	debug;
};

/* Exported via module context. */

static nmsg_res ncap_init(void **clos, int debug);
static nmsg_res ncap_fini(void **clos);
static nmsg_res ncap_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres,
				  const char *el);
static nmsg_res ncap_ipdg_to_pbuf(void *clos, const struct nmsg_ipdg *dg,
				  uint8_t **pbuf, size_t *sz,
				  unsigned *vid, unsigned *msgtype);

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_NCAP_ID, MSGTYPE_NCAP_NAME },
		NMSG_IDNAME_END
	},
	.init = ncap_init,
	.fini = ncap_fini,
	.pbuf_to_pres = ncap_pbuf_to_pres,
	.ipdg_to_pbuf = ncap_ipdg_to_pbuf
};

/* Private. */

static nmsg_res
ncap_init(void **clos, int debug) {
	struct ncap_clos *nclos;

	nclos = *clos = calloc(1, sizeof(*nclos));
	if (nclos == NULL)
		return (nmsg_res_memfail);
	nclos->debug = debug;

	return (nmsg_res_success);
}

static nmsg_res
ncap_fini(void **clos) {
	free(*clos);
	*clos = NULL;
	return (nmsg_res_success);
}

static nmsg_res
ncap_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Ncap *nc;
	char dstip[INET6_ADDRSTRLEN];
	char srcip[INET6_ADDRSTRLEN];
	const struct ip *ip;
	const struct ip6_hdr *ip6;
	const struct udphdr *udp;
	nmsg_res res;
	struct nmsg_ipdg dg;
	struct nmsg_strbuf sbuf;
	unsigned etype;

	dstip[0] = '\0';
	srcip[0] = '\0';
	memset(&sbuf, 0, sizeof(sbuf));

	/* unpack wire format ncap to in-memory struct */
	nc = nmsg__isc__ncap__unpack(NULL, np->payload.len, np->payload.data);
	if (nc == NULL)
		return (nmsg_res_memfail);

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
	default:
		nmsg_asprintf(pres, "unknown ncap type %u%s", nc->type, el);
		return (nmsg_res_success);
		break;
	}

	switch (dg.proto_transport) {
	case IPPROTO_UDP:
		udp = (const struct udphdr *) dg.transport;
		res = nmsg_strbuf_append(&sbuf, "[%s].%hu [%s].%hu udp%s",
					 srcip, ntohs(udp->uh_sport),
					 dstip, ntohs(udp->uh_dport),
					 el);
		if (res != nmsg_res_success)
			return (nmsg_res_failure);
		break;
	default:
		break;
	}

	/* free unneeded in-memory ncap representation */
	nmsg__isc__ncap__free_unpacked(nc, NULL);

	/* export presentation formatted ncap to caller */
	*pres = sbuf.data;

	return (nmsg_res_success);
}

static nmsg_res
ncap_ipdg_to_pbuf(void *clos __attribute__((unused)),
		  const struct nmsg_ipdg *dg,
		  uint8_t **pbuf, size_t *sz,
		  unsigned *vid, unsigned *msgtype)
{
	Nmsg__Isc__Ncap *nc;
	size_t estsz;

	/* initialize in-memory ncap message */
	nc = calloc(1, sizeof(*nc));
	nmsg__isc__ncap__init(nc);

	/* set type */
	switch (dg->proto_network) {
	case PF_INET:
		nc->type = NMSG__ISC__NCAP_TYPE__IPV4;
		break;
	case PF_INET6:
		nc->type = NMSG__ISC__NCAP_TYPE__IPV6;
		break;
	default:
		return (nmsg_res_parse_error);
	}

	/* set payload */
	nc->payload.data = (uint8_t *) dg->network;
	nc->payload.len = dg->len_network;

	/* serialize ncap payload */
	estsz = nc->payload.len + 64 /* ad hoc */;
	*pbuf = malloc(estsz);
	if (*pbuf == NULL) {
		free(nc);
		return (nmsg_res_memfail);
	}
	*sz = nmsg__isc__ncap__pack(nc, *pbuf);

	/* return the vendor id and message type */
	*vid = NMSG_VENDOR_ISC_ID;
	*msgtype = MSGTYPE_NCAP_ID;

	/* the in-memory ncap message is no longer needed */
	free(nc);

	return (nmsg_res_pbuf_ready);
}
