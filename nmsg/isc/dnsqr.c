/* dnsqr nmsg message module */

/*
 * Copyright (c) 2010 by Internet Systems Consortium, Inc. ("ISC")
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

#include <wdns.h>

#include "dnsqr.pb-c.c"

/* Exported via module context. */

static nmsg_res
dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m);

/* Data structures. */

#if 0
typedef struct {
	uint32_t	query_ip;
	uint32_t	response_ip;
	uint16_t	ip_proto;
	uint16_t	query_port;
	uint16_t	response_port;
	uint16_t	id;
	uint16_t	qtype;
	uint16_t	qclass;
	uint8_t		qname[];
} dnsqr_key_t;

typedef struct {
	uint8_t		query_ip6[16];
	uint8_t		response_ip6[16];
	uint16_t	ip_proto;
	uint16_t	query_port;
	uint16_t	response_port;
	uint16_t	id;
	uint16_t	qtype;
	uint16_t	qclass;
	uint8_t		qname[];
} dnsqr_key6_t;
#endif

/* Data. */

struct nmsg_msgmod_field dnsqr_fields[] = {
	{	.type = nmsg_msgmod_ft_enum,	.name = "type"		},
	{	.type = nmsg_msgmod_ft_ip,	.name = "query_ip"	},
	{	.type = nmsg_msgmod_ft_ip,	.name = "response_ip"	},
	{	.type = nmsg_msgmod_ft_uint16,	.name = "ip_proto"	},
	{	.type = nmsg_msgmod_ft_uint16,	.name = "query_port"	},
	{	.type = nmsg_msgmod_ft_uint16,	.name = "response_port"	},
	{	.type = nmsg_msgmod_ft_uint16,	.name = "id"		},

	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "qname",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qclass",
		.print = dns_class_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qtype",
		.print = dns_type_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "query_packets",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "query_time_sec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	{
		.type = nmsg_msgmod_ft_int32,
		.name = "query_time_nsec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response_packets",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "response_time_sec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	{
		.type = nmsg_msgmod_ft_int32,
		.name = "response_time_nsec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	.msgver = NMSG_MSGMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { NMSG_VENDOR_ISC_DNSQR_ID, NMSG_VENDOR_ISC_DNSQR_NAME },

	.pbdescr = &nmsg__isc__dns_qr__descriptor,
	.fields = dnsqr_fields,
	.pkt_to_payload = dnsqr_pkt_to_payload,
};

static nmsg_message_t
dnsqr_to_message(Nmsg__Isc__DnsQR *dnsqr) {
	ProtobufCBufferSimple sbuf;
	size_t buf_sz;

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.data = malloc(1024);
	if (sbuf.data == NULL)
		return (NULL);
	sbuf.must_free_data = 1;
	sbuf.alloced = 1024;

	buf_sz = protobuf_c_message_pack_to_buffer((ProtobufCMessage *) dnsqr,
						   (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL)
		return (NULL);

	return (nmsg_message_from_raw_payload(NMSG_VENDOR_ISC_ID,
					      NMSG_VENDOR_ISC_DNSQR_ID,
					      sbuf.data, buf_sz, NULL));
}

static nmsg_res
do_packet_dns(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, int *qr) {
	const uint8_t *p;
	size_t len;
	size_t t;
	uint8_t *q;
	uint16_t flags;
	uint16_t qtype;
	uint16_t qclass;

	p = dg->payload;
	len = dg->len_payload;

	if (len < 12)
		return (nmsg_res_again);

	dnsqr->id = htons(*((uint16_t *) p));
	flags = htons(*((uint16_t *) (p + 2)));

	p += 12;
	len -= 12;

	*qr = (flags >> 15) & 0x01;

	dnsqr->qname.len = wdns_skip_name(&p, p + len);
	dnsqr->qname.data = malloc(dnsqr->qname.len);
	if (dnsqr->qname.data == NULL)
		return (nmsg_res_memfail);
	len -= dnsqr->qname.len;
	p = dg->payload + 12;
	q = dnsqr->qname.data;

	if (len < 4)
		return (nmsg_res_again);

	t = dnsqr->qname.len;
	while (t-- != 0) {
		*q = *p;
		if (*q >= 'A' && *q <= 'Z')
			*q |= 0x20;
		p++;
		q++;
	}

	memcpy(&qtype, p, 2);
	p += 2;
	memcpy(&qclass, p, 2);
	p += 2;

	dnsqr->qtype = ntohs(qtype);
	dnsqr->qclass = ntohs(qclass);

	return (nmsg_res_success);
}

static nmsg_res
do_packet_udp(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, int *qr) {
	const struct udphdr *udp;
	nmsg_res res;

	res = do_packet_dns(dnsqr, dg, qr);
	if (res != nmsg_res_success)
		return (res);

	udp = (const struct udphdr *) dg->transport;

	if (*qr == 0) {
		/* message is a query */
		dnsqr->query_port = ntohs(udp->uh_sport);
		dnsqr->response_port = ntohs(udp->uh_dport);
	} else {
		/* message is a response */
		dnsqr->query_port = ntohs(udp->uh_dport);
		dnsqr->response_port = ntohs(udp->uh_sport);
	}

	return (nmsg_res_success);
}

static nmsg_res
do_packet_v4(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, int *qr) {
	const struct ip *ip;
	nmsg_res res;
	uint32_t ip4;

	/* allocate query_ip */
	dnsqr->query_ip.len = 4;
	dnsqr->query_ip.data = malloc(4);
	if (dnsqr->query_ip.data == NULL)
		return (nmsg_res_memfail);

	/* allocate response_ip */
	dnsqr->response_ip.len = 4;
	dnsqr->response_ip.data = malloc(4);
	if (dnsqr->response_ip.data == NULL)
		return (nmsg_res_memfail);

	switch (dg->proto_transport) {
	case IPPROTO_UDP:
		res = do_packet_udp(dnsqr, dg, qr);
		break;
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		return (res);

	ip = (const struct ip *) dg->network;

	dnsqr->ip_proto = ip->ip_p;

	if (*qr == 0) {
		/* message is a query */
		memcpy(dnsqr->query_ip.data, &ip->ip_src, 4);
		memcpy(dnsqr->response_ip.data, &ip->ip_dst, 4);
	} else {
		/* message is a response */
		memcpy(dnsqr->query_ip.data, &ip->ip_dst, 4);
		memcpy(dnsqr->response_ip.data, &ip->ip_src, 4);
	}

	return (nmsg_res_success);
}

static nmsg_res
do_packet(nmsg_pcap_t pcap, nmsg_message_t *m,
	  const uint8_t *pkt, struct pcap_pkthdr *pkt_hdr)
{
	Nmsg__Isc__DnsQR *dnsqr = NULL;
	int qr = 0;
	nmsg_res res;
	struct nmsg_ipdg dg;

	res = nmsg_ipdg_parse_pcap_raw(&dg, pcap, pkt_hdr, pkt);
	if (res != nmsg_res_success)
		goto out;

	/* XXX if it's a fragment, do something else here */

	dnsqr = calloc(1, sizeof(*dnsqr));
	if (dnsqr == NULL)
		return (nmsg_res_memfail);
	nmsg__isc__dns_qr__init(dnsqr);

	switch (dg.proto_network) {
	case PF_INET:
		res = do_packet_v4(dnsqr, &dg, &qr);
		break;
#if 0
	case PF_INET6:
		res = do_packet_v6(dnsqr, &dg, &qr);
		break;
#endif
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		goto out;

	if (qr == 0) {
		/* message is a query */

		/* XXX insert into hash table and return */
		dnsqr->type = NMSG__ISC__DNS_QRTYPE__UDP_UNANSWERED_QUERY;
	} else {
		/* message is a response*/

		/* XXX
		 * look up in hash table
		 * if found, merge query and response, generate message, return
		 * else set type to unsolicited response, generate message, return
		 */
		dnsqr->type = NMSG__ISC__DNS_QRTYPE__UDP_UNSOLICITED_RESPONSE;
	}

	*m = dnsqr_to_message(dnsqr);
	if (*m == NULL)
		res = nmsg_res_memfail;

out:
	if (dnsqr != NULL)
		nmsg__isc__dns_qr__free_unpacked(dnsqr, NULL);
	return (res);
}

static nmsg_res
dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m) {
	nmsg_res res;

	/* XXX
	 * expire outstanding queries
	 * set type to unanswered query, generate message, return
	 */

	res = nmsg_res_failure;
	while (res != nmsg_res_success) {
		struct timespec ts;
		struct pcap_pkthdr *pkt_hdr;
		const uint8_t *pkt_data;

		res = nmsg_pcap_input_read_raw(pcap, &pkt_hdr, &pkt_data, &ts);
		if (res == nmsg_res_success) {
			return (do_packet(pcap, m, pkt_data, pkt_hdr));
		} else if (res == nmsg_res_again) {
			continue;
		} else {
			return (res);
		}
	}
	return (res);
}
