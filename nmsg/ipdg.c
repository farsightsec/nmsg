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

#include "nmsg.h"
#include "private.h"

/* Macros. */

#define advance_pkt(pkt, len, sz) do { \
	(pkt) += (sz); \
	(len) -= (sz); \
} while (0)

/* Export. */

nmsg_res
nmsg_ipdg_parse(struct nmsg_ipdg *dg, unsigned etype, size_t len,
		const u_char *pkt)
{
	return (nmsg_ipdg_parse_reasm(dg, etype, len, pkt,
				      NULL, NULL, NULL, NULL, 0));
}

nmsg_res
nmsg_ipdg_parse_pcap(struct nmsg_ipdg *dg, struct nmsg_pcap *pcap,
		     struct pcap_pkthdr *pkt_hdr, const u_char *pkt)
{
	int defrag = 0;
	size_t len = pkt_hdr->caplen;
	unsigned etype = 0;
	unsigned new_len = NMSG_IPSZ_MAX;
	nmsg_res res;

	/* only operate on complete packets */
	if (pkt_hdr->caplen != pkt_hdr->len)
		return (nmsg_res_again);

	/* process data link header */
	switch (pcap->datalink) {
	case DLT_EN10MB: {
		const struct ether_header *eth;

		if (len < sizeof(*eth))
			return (nmsg_res_again);

		eth = (const struct ether_header *) pkt;
		advance_pkt(pkt, len, ETHER_HDR_LEN);
		etype = ntohs(eth->ether_type);
		if (etype == ETHERTYPE_VLAN) {
			if (len < 4)
				return (nmsg_res_again);
			advance_pkt(pkt, len, 2);
			etype = ntohs(*(const uint16_t *) pkt);
			advance_pkt(pkt, len, 2);
		}
		break;
	}
	case DLT_RAW: {
		const struct ip *ip;

		if (len < sizeof(*ip))
			return (nmsg_res_again);
		ip = (const struct ip *) pkt;

		if (ip->ip_v == 4) {
			etype = ETHERTYPE_IP;
		} else if (ip->ip_v == 6) {
			etype = ETHERTYPE_IPV6;
		} else {
			return (nmsg_res_again);
		}
		break;
	}
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL: {
		if (len < 16)
			return (nmsg_res_again);
		advance_pkt(pkt, len, ETHER_HDR_LEN);
		etype = ntohs(*(const uint16_t *) pkt);
		advance_pkt(pkt, len, 2);
		break;
	}
#endif
	} /* end switch */

	res = nmsg_ipdg_parse_reasm(dg, etype, len, pkt, pcap->reasm,
				    &new_len, pcap->new_pkt, &defrag,
				    pkt_hdr->ts.tv_sec);
	if (res == nmsg_res_success && defrag == 1) {
		/* refilter the newly reassembled datagram */
		struct bpf_insn *fcode = pcap->userbpf.bf_insns;

		if (fcode != NULL &&
		    bpf_filter(fcode, dg->network, dg->len_network,
			       dg->len_network) == 0)
		{
			return (nmsg_res_again);
		}
	}
	return (res);
}

nmsg_res
nmsg_ipdg_parse_reasm(struct nmsg_ipdg *dg, unsigned etype, size_t len,
		      const u_char *pkt, nmsg_ipreasm reasm,
		      unsigned *new_len, u_char *new_pkt, int *defrag,
		      uint64_t timestamp)
{
	bool is_fragment = false;
	unsigned frag_hdr_offset = 0;

	dg->network = pkt;
	dg->len_network = len;

	/* process network header */
	switch (etype) {
	case ETHERTYPE_IP: {
		const struct ip *ip;
		unsigned ip_off;

		ip = (const struct ip *) dg->network;
		advance_pkt(pkt, len, ip->ip_hl << 2);

		ip_off = ntohs(ip->ip_off);
		if ((ip_off & IP_OFFMASK) != 0 ||
		    (ip_off & IP_MF) != 0)
		{
			is_fragment = true;
		}
		dg->proto_network = PF_INET;
		dg->proto_transport = ip->ip_p;
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
				is_fragment = true;
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

		advance_pkt(pkt, len, thusfar);

		dg->proto_network = PF_INET6;
		dg->proto_transport = nexthdr;
		break;
	}
	default:
		return (nmsg_res_again);
		break;
	} /* end switch */

	/* handle IPv4 and IPv6 fragments */
	if (is_fragment == true && reasm != NULL) {
		bool rres;

		rres = reasm_ip_next(reasm, dg->network, dg->len_network,
				     frag_hdr_offset, timestamp,
				     new_pkt, new_len);
		if (rres == false || *new_len == 0) {
			/* not all fragments have been received */
			return (nmsg_res_again);
		}
		/* the datagram has been fully reassembled */
		if (defrag != NULL)
			*defrag = 1;
		return (nmsg_ipdg_parse(dg, etype, *new_len, new_pkt));
	}
	if (is_fragment == true && reasm == NULL)
		return (nmsg_res_again);

	dg->transport = pkt;
	dg->len_transport = len;

	/* process transport header */
	switch (dg->proto_transport) {
	case IPPROTO_UDP: {
		if (len < sizeof(struct udphdr))
			return (nmsg_res_again);
		advance_pkt(pkt, len, sizeof(struct udphdr));
		break;
	}
	default:
		return (nmsg_res_again);
		break;
	} /* end switch */

	dg->payload = pkt;
	dg->len_payload = len;

	return (nmsg_res_success);
}
