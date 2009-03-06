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

#include <pcap.h>

#include "datagram.h"
#include "res.h"

/* Macros. */
#define advance_pkt(pkt, len, sz) do { \
	(pkt) += (sz); \
	(len) -= (sz); \
} while (0)

/* Export. */

nmsg_res
nmsg_datagram_find_network(struct nmsg_datagram *dg, int datalink,
			   const u_char *pkt, size_t len)
{
	unsigned etype;
	nmsg_res res = nmsg_res_failure;

	if (datalink == DLT_EN10MB && len >= ETHER_HDR_LEN) {
		const struct ether_header *eth;

		eth = (const struct ether_header *) pkt;
		advance_pkt(pkt, len, ETHER_HDR_LEN);
		etype = ntohs(eth->ether_type);
		if (etype == ETHERTYPE_VLAN && len >= 4) {
			advance_pkt(pkt, len, 2);
			etype = ntohs(*(const uint16_t *) pkt);
			advance_pkt(pkt, len, 2);
		}
		res = nmsg_res_success;
	}
#ifdef DLT_LINUX_SLL
	else if (datalink == DLT_LINUX_SLL && len >= 16) {
		advance_pkt(pkt, len, ETHER_HDR_LEN);
		etype = ntohs(*(const uint16_t *) pkt);
		advance_pkt(pkt, len, 2);
		res = nmsg_res_success;
	}
#endif
	if (res == nmsg_res_success &&
	    (etype == ETHERTYPE_IP || etype == ETHERTYPE_IPV6))
	{
		dg->network = pkt;
		dg->len_network = len;
		dg->proto_network = etype;
	} else {
		res = nmsg_res_failure;
	}

	return (res);
}

int
nmsg_datagram_is_fragment(struct nmsg_datagram *dg) {
	const struct ip *ip;

	if (dg->proto_network == ETHERTYPE_IP) {
		unsigned ip_off;

		ip = (const struct ip *) dg->network;
		ip_off = ntohs(ip->ip_off);
		if ((ip_off & IP_OFFMASK) != 0 ||
		    (ip_off & IP_MF) != 0)
		{
			return (1);
		}

	} else if (dg->proto_network == ETHERTYPE_IPV6) {
		/* XXX */
	}
	return (0);
}

nmsg_res
nmsg_datagram_find_transport(struct nmsg_datagram *dg) {
	const u_char *pkt;
	unsigned len;
	nmsg_res res;

	pkt = dg->network;
	len = dg->len_network;
	res = nmsg_res_failure;

	if (dg->proto_network == ETHERTYPE_IP) {
		const struct ip *ip;

		if (len >= sizeof(*ip)) {
			ip = (const struct ip *) dg->network;
			if (ip->ip_v == IPVERSION) {
				if (len >= ip->ip_hl * 4U) {
					advance_pkt(pkt, len, ip->ip_hl * 4U);
					dg->transport = pkt;
					dg->len_transport = htons(len);
					dg->proto_transport = ip->ip_p;
					res = nmsg_res_success;
				}
			}
		}
	} else if (dg->proto_network == ETHERTYPE_IPV6) {
		/* XXX */
	}

	return (res);
}

nmsg_res
nmsg_datagram_find_payload(struct nmsg_datagram *dg) {
	const u_char *pkt;
	unsigned len;
	nmsg_res res;

	pkt = dg->transport;
	len = dg->len_transport;
	res = nmsg_res_failure;

	if (dg->proto_transport == IPPROTO_UDP) {
		const struct udphdr *udp;

		if (len >= sizeof(*udp)) {
			udp = (const struct udphdr *) dg->transport;
			advance_pkt(pkt, len, sizeof(*udp));
			dg->payload = pkt;
			dg->len_payload = htons(udp->uh_ulen);
			res = nmsg_res_success;
		}
	} else if (dg->proto_transport == IPPROTO_ICMP) {
		/* XXX */
	}

	return (res);
}
