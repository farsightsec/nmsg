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

#include <sys/mman.h>
#include <pthread.h>

#include <wdns.h>

#include "lookup3.h"

#include "dnsqr.pb-c.c"

/* Macros. */

#define NUM_SLOTS	32768
#define MAX_VALUES	20480

/* Exported via module context. */

//nmsg_res dnsqr_init(void **clos);
//nmsg_res dnsqr_fini(void **clos);

//nmsg_res dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m);

/* Data structures. */

typedef struct {
	Nmsg__Isc__DnsQR	*dnsqr;
	uint32_t		fifo_slot;
} hash_entry_t;

typedef struct {
	pthread_mutex_t		lock;

	hash_entry_t		*entries;
	uint32_t		*fifo;

	size_t			len_entries;
	size_t			len_fifo;

	uint32_t		num_slots;
	uint32_t		max_values;
	uint32_t		fifo_idx;
	uint32_t		count;
} dnsqr_ctx_t;

typedef struct {
	uint32_t	query_ip;
	uint32_t	response_ip;
	uint16_t	ip_proto;
	uint16_t	query_port;
	uint16_t	response_port;
	uint16_t	id;
	uint16_t	qtype;
	uint16_t	qclass;
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
} dnsqr_key6_t;

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
		.name = "query_packet",
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
		.name = "response_packet",
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

nmsg_res
dnsqr_init(void **clos) {
	dnsqr_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (nmsg_res_memfail);

	pthread_mutex_init(&ctx->lock, NULL);

	ctx->num_slots = NUM_SLOTS;
	ctx->max_values = MAX_VALUES;

	ctx->len_entries = sizeof(hash_entry_t) * ctx->num_slots;
	ctx->len_fifo = sizeof(uint32_t) * ctx->max_values;

	ctx->entries = mmap(NULL, ctx->len_entries,
			    PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (ctx->entries == MAP_FAILED) {
		free(ctx);
		return (nmsg_res_memfail);
	}

	ctx->fifo = mmap(NULL, ctx->len_fifo,
			 PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (ctx->fifo == MAP_FAILED) {
		munmap(ctx->entries, ctx->len_entries);
		free(ctx);
		return (nmsg_res_memfail);
	}

	*clos = ctx;

	return (nmsg_res_success);
}

nmsg_res
dnsqr_fini(void **clos) {
	size_t n;
	dnsqr_ctx_t *ctx;

	ctx = (dnsqr_ctx_t *) *clos;

	for (n = 0; n < ctx->num_slots; n++) {
		hash_entry_t *he = &ctx->entries[n];
		if (he->dnsqr != NULL)
			nmsg__isc__dns_qr__free_unpacked(he->dnsqr, NULL);
	}

	munmap(ctx->entries, ctx->len_entries);
	munmap(ctx->fifo, ctx->len_fifo);
	free(ctx);
	*clos = NULL;

	return (nmsg_res_success);
}

bool
dnsqr_eq(Nmsg__Isc__DnsQR *d1, Nmsg__Isc__DnsQR *d2) {
	if (d1->id == d2->id &&
	    d1->query_port == d2->query_port &&
	    d1->response_port == d2->response_port &&
	    d1->qname.len == d2->qname.len &&
	    d1->qtype == d2->qtype &&
	    d1->qclass == d2->qclass &&
	    d1->ip_proto == d2->ip_proto &&
	    d1->query_ip.len == d2->query_ip.len &&
	    d1->response_ip.len == d2->response_ip.len)
	{
		if (memcmp(d1->query_ip.data, d2->query_ip.data, d1->query_ip.len) == 0 &&
		    memcmp(d1->response_ip.data, d2->response_ip.data, d1->response_ip.len) == 0 &&
		    memcmp(d1->qname.data, d2->qname.data, d1->qname.len) == 0)
		{
			return (true);
		}
	}

	return (false);
}

uint32_t
dnsqr_hash(Nmsg__Isc__DnsQR *dnsqr) {
	dnsqr_key_t key;
	dnsqr_key6_t key6;
	size_t len;
	void *k;
	uint32_t hash;

	assert(dnsqr->query_ip.len == 4 || dnsqr->query_ip.len == 16);
	assert(dnsqr->response_ip.len == 4 || dnsqr->response_ip.len == 16);

	if (dnsqr->query_ip.len == 4) {
		memcpy(&key.query_ip, dnsqr->query_ip.data, 4);
		memcpy(&key.response_ip, dnsqr->response_ip.data, 4);
		key.ip_proto = dnsqr->ip_proto;
		key.query_port = dnsqr->query_port;
		key.response_port = dnsqr->response_port;
		key.id = dnsqr->id;
		key.qtype = dnsqr->qtype;
		key.qclass = dnsqr->qclass;
		k = &key;
		len = sizeof(key);
	} else if (dnsqr->query_ip.len == 16) {
		memcpy(&key6.query_ip6, dnsqr->query_ip.data, 16);
		memcpy(&key6.response_ip6, dnsqr->response_ip.data, 16);
		key6.ip_proto = dnsqr->ip_proto;
		key6.query_port = dnsqr->query_port;
		key6.response_port = dnsqr->response_port;
		key6.id = dnsqr->id;
		key6.qtype = dnsqr->qtype;
		key6.qclass = dnsqr->qclass;
		k = &key6;
		len = sizeof(key6);
	} else {
		assert(0);
	}

	hash = hashlittle(k, len, 0);
	hash = hashlittle(dnsqr->qname.data, dnsqr->qname.len, hash);
	return (hash);
}

uint32_t
dnsqr_insert_fifo(dnsqr_ctx_t *ctx, uint32_t val) {
	uint32_t ret_idx = ctx->fifo_idx;

	ctx->fifo[ctx->fifo_idx] = val;

	ctx->fifo_idx += 1;
	if (ctx->fifo_idx >= ctx->max_values)
		ctx->fifo_idx = 0;

	return (ret_idx);
}

void
dnsqr_insert_query(dnsqr_ctx_t *ctx, Nmsg__Isc__DnsQR *dnsqr) {
	bool miss = false;
	uint32_t hash;
	unsigned slot, slot_stop;

	hash = dnsqr_hash(dnsqr);
	slot = hash % ctx->num_slots;

	if (slot > 0)
		slot_stop = slot - 1;
	else
		slot_stop = ctx->num_slots - 1;

	/* lock hash table */
	pthread_mutex_lock(&ctx->lock);

	for (;;) {
		hash_entry_t *he = &ctx->entries[slot];

		/* empty slot, insert entry */
		if (he->dnsqr == NULL) {
			ctx->count += 1;
			he->dnsqr = dnsqr;
			he->fifo_slot = dnsqr_insert_fifo(ctx, slot);
			miss = true;
			break;
		}

		/* slot filled */
		assert(slot != slot_stop);
		slot += 1;
		if (slot >= ctx->num_slots)
			slot = 0;
	}

	/* unlock hash table */
	pthread_mutex_unlock(&ctx->lock);
}

void
dnsqr_remove_slot(dnsqr_ctx_t *ctx, unsigned slot) {
	hash_entry_t *he;
	unsigned i, j, k;

	i = j = slot;
	he = &ctx->entries[slot];

	assert(he->dnsqr != NULL);
	he->dnsqr = NULL;
	he->fifo_slot = 0;

	for (;;) {
		/* j is the current slot of the next value */
		j = (j + 1) % ctx->num_slots;
		if (ctx->entries[j].dnsqr == NULL) {
			/* slot is unoccupied */
			break;
		}

		/* k is the natural slot of the value at slot j */
		k = dnsqr_hash(ctx->entries[j].dnsqr) % ctx->num_slots;
		if ((j > i && (k <= i || k > j)) ||
		    (j < i && (k <= i && k > j)))
		{
			/* this value needs to be moved up,
			 * as k is cyclically between i and j */
			memcpy(&ctx->entries[i], &ctx->entries[j], sizeof(hash_entry_t));

			/* fix up the fifo slot index to point to the new slot */
			ctx->fifo[ctx->entries[i].fifo_slot] = i;

			/* delete the value at the old slot */
			memset(&ctx->entries[j], 0, sizeof(hash_entry_t));

			/* check the next slot */
			i = j;
		}
	}
}

Nmsg__Isc__DnsQR *
dnsqr_trim(dnsqr_ctx_t *ctx) {
	Nmsg__Isc__DnsQR *dnsqr;
	int idx;
	unsigned slot;

	if (ctx->count > ctx->max_values) {
		idx = (ctx->fifo_idx - 1) - (ctx->max_values - 1);
		if (idx < 0)
			idx += ctx->max_values;
		slot = ctx->fifo[idx];
		dnsqr = ctx->entries[slot].dnsqr;
		dnsqr_remove_slot(ctx, slot);
		ctx->count -= 1;
		return (dnsqr);
	}

	return (NULL);
}

Nmsg__Isc__DnsQR *
dnsqr_retrieve(dnsqr_ctx_t *ctx, Nmsg__Isc__DnsQR *dnsqr) {
	Nmsg__Isc__DnsQR *query;
	uint32_t hash;
	unsigned slot, slot_stop;

	hash = dnsqr_hash(dnsqr);
	slot = hash % ctx->num_slots;

	if (slot > 0)
		slot_stop = slot - 1;
	else
		slot_stop = ctx->num_slots - 1;

	/* lock hash table */
	pthread_mutex_lock(&ctx->lock);

	for (;;) {
		hash_entry_t *he = &ctx->entries[slot];

		/* empty slot, return failure */
		if (he->dnsqr == NULL) {
			pthread_mutex_unlock(&ctx->lock);
			return (NULL);
		}

		/* slot filled, compare */
		if (dnsqr_eq(dnsqr, he->dnsqr) == true) {
			query = he->dnsqr;
			dnsqr_remove_slot(ctx, slot);
			pthread_mutex_unlock(&ctx->lock);
			return (query);
		}

		/* slot filled, but not our slot */
		assert(slot != slot_stop);
		slot += 1;
		if (slot >= ctx->num_slots)
			slot = 0;
	}

	/* unlock hash table */
	pthread_mutex_unlock(&ctx->lock);
}

nmsg_message_t
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

nmsg_res
do_packet_dns(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, bool *qr) {
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

nmsg_res
do_packet_udp(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, bool *qr) {
	const struct udphdr *udp;
	nmsg_res res;
	uint16_t src_port;
	uint16_t dst_port;

	udp = (const struct udphdr *) dg->transport;
	src_port = ntohs(udp->uh_sport);
	dst_port = ntohs(udp->uh_dport);

	if (!(src_port == 53 || src_port == 5353 || dst_port == 53 || dst_port == 5353))
		return (nmsg_res_again);

	res = do_packet_dns(dnsqr, dg, qr);
	if (res != nmsg_res_success)
		return (res);

	if (*qr == false) {
		/* message is a query */
		dnsqr->query_port = src_port;
		dnsqr->response_port = dst_port;
	} else {
		/* message is a response */
		dnsqr->query_port = dst_port;
		dnsqr->response_port = src_port;
	}

	return (nmsg_res_success);
}

nmsg_res
do_packet_v4(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, bool *qr) {
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

	dnsqr->ip_proto = dg->proto_transport;

	if (*qr == false) {
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

nmsg_res
do_packet_v6(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, bool *qr) {
	const struct ip6_hdr *ip6;
	nmsg_res res;

	/* allocate query_ip */
	dnsqr->query_ip.len = 16;
	dnsqr->query_ip.data = malloc(16);
	if (dnsqr->query_ip.data == NULL)
		return (nmsg_res_memfail);

	/* allocate response_ip */
	dnsqr->response_ip.len = 16;
	dnsqr->response_ip.data = malloc(16);
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

	ip6 = (const struct ip6_hdr *) dg->network;

	dnsqr->ip_proto = dg->proto_transport;

	if (*qr == false) {
		/* message is a query */
		memcpy(dnsqr->query_ip.data, &ip6->ip6_src, 16);
		memcpy(dnsqr->response_ip.data, &ip6->ip6_dst, 16);
	} else {
		/* message is a response */
		memcpy(dnsqr->query_ip.data, &ip6->ip6_dst, 16);
		memcpy(dnsqr->response_ip.data, &ip6->ip6_src, 16);
	}

	return (nmsg_res_success);
}

void
dnsqr_merge(Nmsg__Isc__DnsQR *d1, Nmsg__Isc__DnsQR *d2) {
	assert(d2->n_query_packet == 0 &&
	       d2->n_query_time_sec == 0 &&
	       d2->n_query_time_nsec == 0 &&
	       d2->query_packet == NULL &&
	       d2->query_time_sec == NULL &&
	       d2->query_time_nsec == NULL);

	d2->n_query_packet = d1->n_query_packet;
	d2->n_query_time_sec = d1->n_query_time_sec;
	d2->n_query_time_nsec = d1->n_query_time_nsec;
	d2->query_packet = d1->query_packet;
	d2->query_time_sec = d1->query_time_sec;
	d2->query_time_nsec = d1->query_time_nsec;

	d1->n_query_packet = 0;
	d1->n_query_time_sec = 0;
	d1->n_query_time_nsec = 0;
	d1->query_packet = NULL;
	d1->query_time_sec = NULL;
	d1->query_time_nsec = NULL;

	nmsg__isc__dns_qr__free_unpacked(d1, NULL);
}

#define extend_field_array(x) \
do { \
	void *_tmp = (x); \
	(x) = realloc((x), n * sizeof(*(x))); \
	if ((x) == NULL) { \
		(x) = _tmp; \
		return (nmsg_res_memfail); \
	} \
} while(0)

nmsg_res
dnsqr_append_query_packet(Nmsg__Isc__DnsQR *dnsqr,
			  const uint8_t *pkt, const struct pcap_pkthdr *pkt_hdr,
			  const struct timespec *ts)
{
	size_t n, idx;
	uint8_t *pkt_copy;

	n = idx = dnsqr->n_query_packet;
	n += 1;

	extend_field_array(dnsqr->query_packet);
	extend_field_array(dnsqr->query_time_sec);
	extend_field_array(dnsqr->query_time_nsec);

	pkt_copy = malloc(pkt_hdr->caplen);
	if (pkt_copy == NULL)
		return (nmsg_res_memfail);
	memcpy(pkt_copy, pkt, pkt_hdr->caplen);

	dnsqr->n_query_packet += 1;
	dnsqr->n_query_time_sec += 1;
	dnsqr->n_query_time_nsec += 1;

	dnsqr->query_packet[idx].len = pkt_hdr->caplen;
	dnsqr->query_packet[idx].data = pkt_copy;
	dnsqr->query_time_sec[idx] = ts->tv_sec;
	dnsqr->query_time_nsec[idx] = ts->tv_nsec;

	return (nmsg_res_success);
}

nmsg_res
do_packet(dnsqr_ctx_t *ctx, nmsg_pcap_t pcap, nmsg_message_t *m,
	  const uint8_t *pkt, const struct pcap_pkthdr *pkt_hdr,
	  const struct timespec *ts)
{
	Nmsg__Isc__DnsQR *dnsqr = NULL;
	bool qr = 0;
	nmsg_res res;
	struct nmsg_ipdg dg;

	res = nmsg_ipdg_parse_pcap_raw(&dg, pcap, pkt_hdr, pkt);
	if (res != nmsg_res_success)
		return (res);

	/* XXX if it's a fragment, do something else here */

	dnsqr = calloc(1, sizeof(*dnsqr));
	if (dnsqr == NULL)
		return (nmsg_res_memfail);
	nmsg__isc__dns_qr__init(dnsqr);

	switch (dg.proto_network) {
	case PF_INET:
		res = do_packet_v4(dnsqr, &dg, &qr);
		break;
	case PF_INET6:
		res = do_packet_v6(dnsqr, &dg, &qr);
		break;
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		goto out;

	if (qr == 0) {
		/* message is a query */
		dnsqr->type = NMSG__ISC__DNS_QRTYPE__UDP_UNANSWERED_QUERY;
		res = dnsqr_append_query_packet(dnsqr, pkt, pkt_hdr, ts);
		if (res != nmsg_res_success)
			goto out;
		dnsqr_insert_query(ctx, dnsqr);
		dnsqr = NULL;
		res = nmsg_res_again;
	} else {
		/* message is a response */
		Nmsg__Isc__DnsQR *query;

		query = dnsqr_retrieve(ctx, dnsqr);
		if (query == NULL) {
			/* no corresponding query, this is an unsolicited response */
			dnsqr->type = NMSG__ISC__DNS_QRTYPE__UDP_UNSOLICITED_RESPONSE;
			*m = dnsqr_to_message(dnsqr);
			if (*m == NULL) {
				res = nmsg_res_memfail;
				goto out;
			}
			res = nmsg_res_success;
		} else {
			/* corresponding query, merge query and response */
			dnsqr->type = NMSG__ISC__DNS_QRTYPE__UDP_QUERY_RESPONSE;
			dnsqr_merge(query, dnsqr);
			*m = dnsqr_to_message(dnsqr);
			if (*m == NULL) {
				res = nmsg_res_memfail;
				goto out;
			}
			res = nmsg_res_success;
		}
	}

out:
	if (dnsqr != NULL)
		nmsg__isc__dns_qr__free_unpacked(dnsqr, NULL);
	return (res);
}

nmsg_res
dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m) {
	Nmsg__Isc__DnsQR *dnsqr;
	dnsqr_ctx_t *ctx = (dnsqr_ctx_t *) clos;
	nmsg_res res;

	/* XXX
	 * expire outstanding queries
	 * set type to unanswered query, generate message, return
	 */

	dnsqr = dnsqr_trim(ctx);
	if (dnsqr != NULL) {
		*m = dnsqr_to_message(dnsqr);
		nmsg__isc__dns_qr__free_unpacked(dnsqr, NULL);
		return (nmsg_res_success);
	}

	res = nmsg_res_failure;
	while (res != nmsg_res_success) {
		struct timespec ts;
		struct pcap_pkthdr *pkt_hdr;
		const uint8_t *pkt_data;

		res = nmsg_pcap_input_read_raw(pcap, &pkt_hdr, &pkt_data, &ts);
		if (res == nmsg_res_success) {
			return (do_packet(ctx, pcap, m, pkt_data, pkt_hdr, &ts));
		} else if (res == nmsg_res_again) {
			continue;
		} else if (res == nmsg_res_eof) {
			size_t n;
			for (n = 0; n < ctx->num_slots; n++) {
				hash_entry_t *he = &ctx->entries[n];
				if (he->dnsqr != NULL) {
					*m = dnsqr_to_message(he->dnsqr);
					nmsg__isc__dns_qr__free_unpacked(he->dnsqr, NULL);
					he->dnsqr = NULL;
					return (nmsg_res_success);
				}
			}
			return (res);
		} else {
			return (res);
		}
	}
	return (res);
}

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	.msgver = NMSG_MSGMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { NMSG_VENDOR_ISC_DNSQR_ID, NMSG_VENDOR_ISC_DNSQR_NAME },

	.pbdescr = &nmsg__isc__dns_qr__descriptor,
	.fields = dnsqr_fields,
	.init = dnsqr_init,
	.fini = dnsqr_fini,
	.pkt_to_payload = dnsqr_pkt_to_payload,
};
