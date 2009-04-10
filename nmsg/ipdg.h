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

#ifndef NMSG_IPDG_H
#define NMSG_IPDG_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/ipdg.h
 * \brief IP datagram utility functions.
 */

/***
 *** Imports
 ***/

#include <sys/types.h>

#include <pcap.h>

#include <nmsg.h>

/***
 *** Types
 ***/

struct nmsg_ipdg {
	int		proto_network;
	int		proto_transport;
	unsigned	len_network;
	unsigned	len_transport;
	unsigned	len_payload;
	const u_char	*network;
	const u_char	*transport;
	const u_char	*payload;
};

/***
 *** Functions
 ***/

nmsg_res
nmsg_ipdg_parse(struct nmsg_ipdg *dg, unsigned etype, size_t len,
		const u_char *pkt);
/*%<
 * Parse an IP datagram and populate a struct nmsg_ipdg indicating where
 * the network, transport, and payload sections of the datagram are and the
 * length of the remaining packet at each of those sections.
 *
 * This function operates on datagrams from the network layer.
 *
 * Broken and fragmented datagrams are discarded.
 *
 * Requires:
 *
 * \li	'dg' is a caller-allocated struct nmsg_ipdg which will be populated
 *	after a successful call.
 *
 * \li	'etype' is an ETHERTYPE_* value. The only supported values are
 *	ETHERTYPE_IP and ETHERTYPE_IPV6.
 *
 * \li	'len' is the length of the packet.
 *
 * \li	'pkt' is a pointer to the packet.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_again
 */

nmsg_res
nmsg_ipdg_parse_pcap(struct nmsg_ipdg *dg, nmsg_pcap_t pcap,
		     struct pcap_pkthdr *pkt_hdr, const u_char *pkt);
/*%<
 * Parse an IP datagram and populate a struct nmsg_ipdg indicating where
 * the network, transport, and payload sections of the datagram are and the
 * length of the remaining packet at each of those sections.
 *
 * This function operates on raw frames returned by libpcap from the data
 * link layer. The packet beginning at 'pkt' must match the datalink type
 * associated with 'pcap' and must be pkt_hdr->caplen octets long.
 *
 * Broken packets are discarded. All but the final fragment of a fragmented
 * datagram are stored internally and nmsg_res_again is returned.
 *
 * Requires:
 *
 * \li	'dg' is a caller-allocated struct nmsg_ipdg which will be populated
 *	after a successful call.
 *
 * \li	'pcap' is a caller-initialized nmsg_pcap object from whose pcap
 *	handle the packet 'pkt' was received.
 *
 * \li	'pkt_hdr' is a pointer to the pcap packet header corresponding
 *	to 'pkt'.
 *
 * \li	'pkt' is a pointer to the packet.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_again
 */

nmsg_res
nmsg_ipdg_parse_reasm(struct nmsg_ipdg *dg, unsigned etype, size_t len,
		      const u_char *pkt, nmsg_ipreasm_t reasm,
		      unsigned *new_len, u_char *new_pkt, int *defrag,
		      uint64_t timestamp);
/*%<
 * Parse an IP datagram and populate a struct nmsg_ipdg indicating where
 * the network, transport, and payload sections of the datagram are and the
 * length of the remaining packet at each of those sections.
 *
 * This function operates on datagrams from the network layer.
 *
 * Broken packets are discarded. All but the final fragment of a fragmented
 * datagram are stored internally and nmsg_res_again is returned.
 *
 * Calling this function with the last four parameters set to NULL or 0 is
 * equivalent to calling nmsg_ipdg_parse().
 *
 * Requires:
 *
 * \li	'dg' is a caller-allocated struct nmsg_ipdg which will be populated
 *	after a successful call.
 *
 * \li	'etype' is an ETHERTYPE_* value. The only supported values are
 *	ETHERTYPE_IP and ETHERTYPE_IPV6.
 *
 * \li	'len' is the length of the packet.
 *
 * \li	'pkt' is a pointer to the packet.
 *
 * \li	'reasm' is a caller-initialized struct reasm_ip object.
 *
 * \li	'new_len' is a parameter-return value indicating the length of
 *	'new_pkt'. If IP reassembly is performed, its value after return
 *	is the length of the reassembled IP datagram stored in 'new_pkt'.
 *
 * \li	'new_pkt' is a buffer of at least '*new_len' bytes where a
 *	reassembled IP datagram will be stored if reassembly is performed.
 *
 * \li	'timestamp' is an arbitrary timestamp, such as seconds since the
 *	unix epoch.
 *
 * \li	'defrag' is NULL, or a pointer to where the value 1 will be stored if
 *	successful defragmentation occurs.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_again
 */

#endif /* NMSG_IPDG_H */
