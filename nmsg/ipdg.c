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

#include <string.h>

#include <pcap.h>

#include "ipdg.h"
#include "private.h"
#include "res.h"

/* Macros. */

#define advance_pkt(pkt, len, sz) do { \
	(pkt) += (sz); \
	(len) -= (sz); \
} while (0)

/* Export. */

nmsg_res
nmsg_ipdg_find_network(struct nmsg_ipdg *dg, struct nmsg_pcap *pcap,
		       const u_char *pkt, struct pcap_pkthdr *pkt_hdr)
{
	int is_fragment;
	nmsg_res res;
	size_t len;
	unsigned etype;
	unsigned frag_hdr_offset;

	frag_hdr_offset = 0;
	is_fragment = 0;
	len = pkt_hdr->caplen;
	res = nmsg_res_failure;

	if (pcap->datalink == DLT_EN10MB && len >= ETHER_HDR_LEN) {
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
	else if (pcap->datalink == DLT_LINUX_SLL && len >= 16) {
		advance_pkt(pkt, len, ETHER_HDR_LEN);
		etype = ntohs(*(const uint16_t *) pkt);
		advance_pkt(pkt, len, 2);
		res = nmsg_res_success;
	}
#endif

	if (res != nmsg_res_success)
		return (res);

	dg->network = pkt;
	dg->len_network = len;

	switch (etype) {
	case ETHERTYPE_IP: {
		const struct ip *ip;
		unsigned ip_off;

		ip = (const struct ip *) dg->network;
		ip_off = ntohs(ip->ip_off);
		if ((ip_off & IP_OFFMASK) != 0 ||
		    (ip_off & IP_MF) != 0)
		{
			is_fragment = 1;
		}
		dg->proto_network = PF_INET;
		break;
	}
	case ETHERTYPE_IPV6: {
		const struct ip6_hdr *ip6;
		uint16_t payload_len;
		uint8_t nexthdr;
		unsigned thusfar;

		if (len < sizeof(*ip6))
			return (nmsg_res_again);
		ip6 = (const struct ip6_hdr *) dg->network;
		if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
			return (nmsg_res_again);

		nexthdr = ip6->ip6_nxt;
		thusfar = sizeof(struct ip6_hdr);
		payload_len = ntohs(ip6->ip6_plen);

		while (nexthdr == IPPROTO_ROUTING ||
		       nexthdr == IPPROTO_HOPOPTS ||
		       nexthdr == IPPROTO_FRAGMENT ||
		       nexthdr == IPPROTO_DSTOPTS ||
		       nexthdr == IPPROTO_AH ||
		       nexthdr == IPPROTO_ESP)
		{
			struct {
				uint8_t nexthdr;
				uint8_t length;
			} ext_hdr;
			uint16_t ext_hdr_len;

			/* catch broken packets */
			if ((thusfar + sizeof(ext_hdr)) > len)
			    return (nmsg_res_again);

			if (nexthdr == IPPROTO_FRAGMENT) {
				frag_hdr_offset = thusfar;
				is_fragment = 1;
				break;
			}

			memcpy(&ext_hdr, (const u_char *) ip6 + thusfar,
			       sizeof(ext_hdr));
			nexthdr = ext_hdr.nexthdr;
			ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

			if (ext_hdr_len > payload_len)
				return (nmsg_res_again);

			thusfar += ext_hdr_len;
			payload_len -= ext_hdr_len;
		}

		if ((thusfar + payload_len) > len || payload_len == 0)
			return (nmsg_res_again);

		dg->proto_network = PF_INET6;
		break;
	}
	default:
		res = nmsg_res_failure;
		break;
	} /* end switch */

	if (is_fragment) {
		bool rres;
		unsigned new_len = NMSG_IPSZ_MAX;

		rres = reasm_ip_next(pcap->reasm, pkt, len, frag_hdr_offset,
				     pkt_hdr->ts.tv_sec, pcap->new_pkt,
				     &new_len);
		if (rres == false || new_len == 0)
			return (nmsg_res_again);
		dg->network = pcap->new_pkt;
		dg->len_network = new_len;
	}

	return (res);
}

nmsg_res
nmsg_ipdg_find_transport(struct nmsg_ipdg *dg) {
	const u_char *pkt;
	unsigned len;
	nmsg_res res;

	pkt = dg->network;
	len = dg->len_network;
	res = nmsg_res_failure;

	switch (dg->proto_network) {
	case PF_INET: {
		const struct ip *ip;

		if (len < sizeof(*ip))
			break;
		ip = (const struct ip *) dg->network;

		if (ip->ip_v != IPVERSION)
			break;

		if (len <= ip->ip_hl * 4U)
			break;

		advance_pkt(pkt, len, ip->ip_hl * 4U);
		dg->transport = pkt;
		dg->len_transport = len;
		dg->proto_transport = ip->ip_p;
		res = nmsg_res_success;
	}
	case PF_INET6: {
		const struct ip6_hdr *ip6;
		uint16_t payload_len;
		uint8_t nexthdr;
		unsigned thusfar;

		if (len < sizeof(*ip6))
			return (nmsg_res_again);
		ip6 = (const struct ip6_hdr *) dg->network;
		if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
			return (nmsg_res_again);

		nexthdr = ip6->ip6_nxt;
		thusfar = sizeof(struct ip6_hdr);
		payload_len = ntohs(ip6->ip6_plen);

		while (nexthdr == IPPROTO_ROUTING ||
		       nexthdr == IPPROTO_HOPOPTS ||
		       nexthdr == IPPROTO_DSTOPTS ||
		       nexthdr == IPPROTO_AH ||
		       nexthdr == IPPROTO_ESP)
		{
			struct {
				uint8_t nexthdr;
				uint8_t length;
			} ext_hdr;
			uint16_t ext_hdr_len;

			/* catch broken packets */
			if ((thusfar + sizeof(ext_hdr)) > len)
			    return (nmsg_res_again);

			memcpy(&ext_hdr, (const u_char *) ip6 + thusfar,
			       sizeof(ext_hdr));
			nexthdr = ext_hdr.nexthdr;
			ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

			if (ext_hdr_len > payload_len)
				return (nmsg_res_again);

			thusfar += ext_hdr_len;
			payload_len -= ext_hdr_len;
		}

		if ((thusfar + payload_len) > len || payload_len == 0)
			return (nmsg_res_again);

		dg->proto_transport = nexthdr;
		dg->len_transport = payload_len;
		res = nmsg_res_success;
	}
	default:
		break;
	} /* end switch */

	return (res);
}

nmsg_res
nmsg_ipdg_find_payload(struct nmsg_ipdg *dg) {
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
			dg->len_payload = len;
			res = nmsg_res_success;
		}
	} else if (dg->proto_transport == IPPROTO_ICMP) {
		/* XXX */
	}

	return (res);
}
