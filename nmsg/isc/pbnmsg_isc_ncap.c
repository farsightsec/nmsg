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

	nc = nmsg__isc__ncap__unpack(NULL, np->payload.len, np->payload.data);
	if (nc == NULL)
		return (nmsg_res_memfail);

	nmsg_asprintf(pres, "network_type=%d transport_type=%d%s",
		      nc->network_type, nc->transport_type, el);

	nmsg__isc__ncap__free_unpacked(nc, NULL);

	return (nmsg_res_success);
}

static nmsg_res
ncap_ipdg_to_pbuf(void *clos, const struct nmsg_ipdg *dg,
		  uint8_t **pbuf, size_t *sz,
		  unsigned *vid, unsigned *msgtype)
{
	Nmsg__Isc__Ncap *nc;
	size_t estsz;
	struct ncap_clos *nclos = (struct ncap_clos *) clos;

	fprintf(stderr, "%s: nclos=%p dg=%p pbuf=%p sz=%p\n",
		__func__, nclos, dg, pbuf, sz);

	/* initialize in-memory ncap message */
	nc = calloc(1, sizeof(*nc));
	nmsg__isc__ncap__init(nc);

	/* load network_type value */
	switch (dg->proto_network) {
	case ETHERTYPE_IP:
		nc->network_type = NMSG__ISC__NETWORK__IP4;
		break;
	case ETHERTYPE_IPV6:
		nc->network_type = NMSG__ISC__NETWORK__IP6;
		break;
	default:
		if (nclos->debug > 0)
			fprintf(stderr, "%s: unexpected proto_network value "
				"%d\n", __func__, dg->proto_network);
	}

	/* load transport_type value */
	switch (dg->proto_transport) {
	case IPPROTO_UDP:
		nc->transport_type = NMSG__ISC__TRANSPORT__UDP;
		break;
	default:
		if (nclos->debug > 0)
			fprintf(stderr, "%s: unexpected proto_transport value "
				"%d\n", __func__, dg->proto_transport);
	}

	/* load srcip and dstip values */
	if (nc->network_type == NMSG__ISC__NETWORK__IP4) {
		const struct ip *ip = (const struct ip *) dg->network;

		nc->srcip.data = malloc(4);
		nc->dstip.data = malloc(4);
		if (nc->srcip.data == NULL || nc->dstip.data == NULL) {
			free(nc);
			return (nmsg_res_memfail);
		}
		nc->srcip.len = nc->dstip.len = 4;

		memcpy(nc->srcip.data, &ip->ip_src.s_addr, 4);
		memcpy(nc->dstip.data, &ip->ip_dst.s_addr, 4);
	} else if (nc->network_type == NMSG__ISC__NETWORK__IP6) {
		const struct ip6_hdr *ip6 =
			(const struct ip6_hdr *) dg->network;

		nc->srcip.data = malloc(16);
		nc->dstip.data = malloc(16);
		if (nc->srcip.data == NULL || nc->dstip.data == NULL) {
			free(nc);
			return (nmsg_res_memfail);
		}
		nc->srcip.len = nc->dstip.len = 16;

		memcpy(nc->srcip.data, ip6->ip6_src.s6_addr, 16);
		memcpy(nc->dstip.data, ip6->ip6_dst.s6_addr, 16);
	}

	/* load tp_i0 and tp_i1 values */
	if (nc->transport_type == NMSG__ISC__TRANSPORT__UDP) {
		const struct udphdr *udp =
			(const struct udphdr *) dg->transport;

		nc->tp_i0 = ntohs(udp->uh_sport);
		nc->tp_i1 = ntohs(udp->uh_dport);
		nc->has_tp_i0 = 1;
		nc->has_tp_i1 = 1;
	} /* else XXX */

	/* set payload */
	nc->payload.data = (uint8_t *) dg->payload;
	nc->payload.len = dg->len_payload;

	/* serialize ncap payload */
	estsz = 64 + dg->len_network;
	*pbuf = malloc(estsz);
	if (*pbuf == NULL) {
		free(nc->srcip.data);
		free(nc->dstip.data);
		free(nc);
		return (nmsg_res_memfail);
	}
	*sz = nmsg__isc__ncap__pack(nc, *pbuf);

	/* return the vendor id and message type */
	*vid = NMSG_VENDOR_ISC_ID;
	*msgtype = MSGTYPE_NCAP_ID;

	/* the in-memory ncap message is no longer needed */
	free(nc->srcip.data);
	free(nc->dstip.data);
	free(nc);

	return (nmsg_res_pbuf_ready);
}
