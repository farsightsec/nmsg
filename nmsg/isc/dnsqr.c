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

#define NUM_SLOTS	262144
#define MAX_VALUES	131072

#define QUERY_TIMEOUT	30

#define DNS_FLAG_QR(flags)	(((flags) >> 15) & 0x01)
#define DNS_FLAG_RCODE(flags)	((flags) & 0xf)

/* Data structures. */

#define DEBUG 1

typedef struct list_entry list_entry_t;
typedef struct hash_entry hash_entry_t;

struct list_entry {
	ISC_LINK(struct list_entry)	link;
	hash_entry_t			*he;
};

struct hash_entry {
	Nmsg__Isc__DnsQR		*dnsqr;
	list_entry_t			*le;
};

typedef struct {
	pthread_mutex_t			lock;

	hash_entry_t			*table;
	ISC_LIST(struct list_entry)	list;

	size_t				len_table;

	bool				stop;

	uint32_t			num_slots;
	uint32_t			max_values;
	uint32_t			count;
#ifdef DEBUG
	uint32_t			count_unanswered_query;
	uint32_t			count_unsolicited_response;
	uint32_t			count_query_response;
	uint32_t			count_packet;
#endif
	struct timespec			now;
} dnsqr_ctx_t;

typedef struct {
	uint32_t			query_ip;
	uint32_t			response_ip;
	uint16_t			ip_proto;
	uint16_t			query_port;
	uint16_t			response_port;
	uint16_t			id;
} dnsqr_key_t;

typedef struct {
	uint8_t				query_ip6[16];
	uint8_t				response_ip6[16];
	uint16_t			ip_proto;
	uint16_t			query_port;
	uint16_t			response_port;
	uint16_t			id;
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

/* Exported via module context. */

//nmsg_res dnsqr_init(void **clos);
//nmsg_res dnsqr_fini(void **clos);

//nmsg_res dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m);

void dnsqr_print_stats(dnsqr_ctx_t *ctx);

/* Functions. */

nmsg_res
dnsqr_init(void **clos) {
	dnsqr_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (nmsg_res_memfail);

	pthread_mutex_init(&ctx->lock, NULL);

	ctx->num_slots = NUM_SLOTS;
	ctx->max_values = MAX_VALUES;

	ctx->len_table = sizeof(hash_entry_t) * ctx->num_slots;

	ctx->table = mmap(NULL, ctx->len_table,
			  PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (ctx->table == MAP_FAILED) {
		free(ctx);
		return (nmsg_res_memfail);
	}

	ISC_LIST_INIT(ctx->list);

	*clos = ctx;

	return (nmsg_res_success);
}

nmsg_res
dnsqr_fini(void **clos) {
	size_t n;
	dnsqr_ctx_t *ctx;

	ctx = (dnsqr_ctx_t *) *clos;

	for (n = 0; n < ctx->num_slots; n++) {
		hash_entry_t *he = &ctx->table[n];
		if (he->dnsqr != NULL)
			nmsg__isc__dns_qr__free_unpacked(he->dnsqr, NULL);
	}

	dnsqr_print_stats(ctx);

	munmap(ctx->table, ctx->len_table);
	free(ctx);
	*clos = NULL;

	return (nmsg_res_success);
}

bool
dnsqr_eq6(Nmsg__Isc__DnsQR *d1, Nmsg__Isc__DnsQR *d2) {
	if (d1->id == d2->id &&
	    d1->query_port == d2->query_port &&
	    d1->response_port == d2->response_port &&
	    d1->ip_proto == d2->ip_proto &&
	    d1->query_ip.len == d2->query_ip.len &&
	    d1->response_ip.len == d2->response_ip.len)
	{
		if (memcmp(d1->query_ip.data, d2->query_ip.data, d1->query_ip.len) == 0 &&
		    memcmp(d1->response_ip.data, d2->response_ip.data, d1->response_ip.len) == 0)
		{
			return (true);
		}
	}

	return (false);
}

bool
dnsqr_eq9(Nmsg__Isc__DnsQR *d1, Nmsg__Isc__DnsQR *d2) {
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

bool
dnsqr_eq(Nmsg__Isc__DnsQR *d1, Nmsg__Isc__DnsQR *d2, uint16_t rcode) {
	if (d1->qname.data != NULL && d2->qname.data != NULL) {
		return (dnsqr_eq9(d1, d2));
	} else {
		switch (rcode) {
		case WDNS_R_FORMERR:
		case WDNS_R_SERVFAIL:
		case WDNS_R_NOTIMP:
		case WDNS_R_REFUSED:
			return (dnsqr_eq6(d1, d2));
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
		k = &key;
		len = sizeof(key);
	} else if (dnsqr->query_ip.len == 16) {
		memcpy(&key6.query_ip6, dnsqr->query_ip.data, 16);
		memcpy(&key6.response_ip6, dnsqr->response_ip.data, 16);
		key6.ip_proto = dnsqr->ip_proto;
		key6.query_port = dnsqr->query_port;
		key6.response_port = dnsqr->response_port;
		key6.id = dnsqr->id;
		k = &key6;
		len = sizeof(key6);
	} else {
		assert(0);
	}

	hash = hashlittle(k, len, 0);
	return (hash);
}

void
dnsqr_insert_query(dnsqr_ctx_t *ctx, Nmsg__Isc__DnsQR *dnsqr) {
	bool miss = false;
	list_entry_t *le;
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
		hash_entry_t *he = &ctx->table[slot];

		/* empty slot, insert entry */
		if (he->dnsqr == NULL) {
			miss = true;
			ctx->count += 1;
			he->dnsqr = dnsqr;

			le = calloc(1, sizeof(*le));
			assert(le != NULL);
			le->he = he;
			he->le = le;
			ISC_LINK_INIT(le, link);
			ISC_LIST_APPEND(ctx->list, le, link);
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
dnsqr_remove(dnsqr_ctx_t *ctx, hash_entry_t *he) {
	unsigned slot;
	unsigned i, j, k;

	i = j = slot = (he - ctx->table);

	assert(he->dnsqr != NULL);
	he->dnsqr = NULL;
	ctx->count -= 1;
	ISC_LIST_UNLINK(ctx->list, he->le, link);
	free(he->le);
	he->le = NULL;

	for (;;) {
		/* j is the current slot of the next value */
		j = (j + 1) % ctx->num_slots;
		if (ctx->table[j].dnsqr == NULL) {
			/* slot is unoccupied */
			break;
		}

		/* k is the natural slot of the value at slot j */
		k = dnsqr_hash(ctx->table[j].dnsqr) % ctx->num_slots;
		if ((j > i && (k <= i || k > j)) ||
		    (j < i && (k <= i && k > j)))
		{
			/* this value needs to be moved up,
			 * as k is cyclically between i and j */
			memcpy(&ctx->table[i], &ctx->table[j], sizeof(hash_entry_t));

			/* delete the value at the old slot */
			memset(&ctx->table[j], 0, sizeof(hash_entry_t));

			/* fix up the list pointer */
			ctx->table[i].le->he = &ctx->table[i];

			/* check the next slot */
			i = j;
		}
	}
}

Nmsg__Isc__DnsQR *
dnsqr_trim(dnsqr_ctx_t *ctx, const struct timespec *ts) {
	Nmsg__Isc__DnsQR *dnsqr = NULL;
	list_entry_t *le;
	hash_entry_t *he;

	/* lock hash table */
	pthread_mutex_lock(&ctx->lock);

	le = ISC_LIST_HEAD(ctx->list);

	if (le != NULL) {
		assert(le->he != NULL);
		he = le->he;
		assert(he->dnsqr != NULL);
		assert(he->dnsqr->n_query_time_sec > 0);
		if (ctx->count > ctx->max_values ||
		    ctx->stop == true ||
		    ts->tv_sec - he->dnsqr->query_time_sec[0] > QUERY_TIMEOUT)
		{
			dnsqr = he->dnsqr;
			dnsqr_remove(ctx, he);
			ctx->count_unanswered_query += 1;
		}
	}

	/* unlock hash table */
	pthread_mutex_unlock(&ctx->lock);

	return (dnsqr);
}

Nmsg__Isc__DnsQR *
dnsqr_retrieve(dnsqr_ctx_t *ctx, Nmsg__Isc__DnsQR *dnsqr, uint16_t rcode) {
	Nmsg__Isc__DnsQR *query = NULL;
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
		hash_entry_t *he = &ctx->table[slot];

		/* empty slot, return failure */
		if (he->dnsqr == NULL) {
			query = NULL;
			goto out;
		}

		/* slot filled, compare */
		if (dnsqr_eq(dnsqr, he->dnsqr, rcode) == true) {
			query = he->dnsqr;
			dnsqr_remove(ctx, he);
			goto out;
		}

		/* slot filled, but not our slot */
		assert(slot != slot_stop);
		slot += 1;
		if (slot >= ctx->num_slots)
			slot = 0;
	}

out:
	/* unlock hash table */
	pthread_mutex_unlock(&ctx->lock);

	return (query);
}

nmsg_message_t
dnsqr_to_message(Nmsg__Isc__DnsQR *dnsqr) {
	ProtobufCBufferSimple sbuf;
	nmsg_message_t m;
	size_t buf_sz;
	struct timespec ts;

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

	m = nmsg_message_from_raw_payload(NMSG_VENDOR_ISC_ID,
					  NMSG_VENDOR_ISC_DNSQR_ID,
					  sbuf.data, buf_sz, NULL);

	if (dnsqr->n_query_time_sec > 0) {
		ts.tv_sec = dnsqr->query_time_sec[0];
		ts.tv_nsec = dnsqr->query_time_nsec[0];
		nmsg_message_set_time(m, &ts);
	} else if (dnsqr->n_response_time_sec > 0) {
		ts.tv_sec = dnsqr->response_time_sec[0];
		ts.tv_nsec = dnsqr->response_time_nsec[0];
		nmsg_message_set_time(m, &ts);
	}

	return (m);
}

nmsg_res
do_packet_dns(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const uint8_t *p;
	size_t len;
	size_t t;
	uint8_t *q;
	uint16_t qdcount;
	uint16_t qtype;
	uint16_t qclass;

	p = dg->payload;
	len = dg->len_payload;

	if (len < 12)
		return (nmsg_res_again);

	dnsqr->id = htons(*((uint16_t *) p));
	*flags = htons(*((uint16_t *) (p + 2)));
	qdcount = htons(*((uint16_t *) (p + 4)));

	p += 12;
	len -= 12;

	if (qdcount == 1 && len > 0) {
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
	}

	return (nmsg_res_success);
}

nmsg_res
do_packet_udp(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const struct udphdr *udp;
	nmsg_res res;
	uint16_t src_port;
	uint16_t dst_port;

	udp = (const struct udphdr *) dg->transport;
	src_port = ntohs(udp->uh_sport);
	dst_port = ntohs(udp->uh_dport);

	if (!(src_port == 53 || src_port == 5353 || dst_port == 53 || dst_port == 5353))
		return (nmsg_res_again);

	res = do_packet_dns(dnsqr, dg, flags);
	if (res != nmsg_res_success)
		return (res);

	if (DNS_FLAG_QR(*flags) == false) {
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
do_packet_v4(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
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
		res = do_packet_udp(dnsqr, dg, flags);
		break;
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		return (res);

	ip = (const struct ip *) dg->network;

	dnsqr->ip_proto = dg->proto_transport;

	if (DNS_FLAG_QR(*flags) == false) {
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
do_packet_v6(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
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
		res = do_packet_udp(dnsqr, dg, flags);
		break;
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		return (res);

	ip6 = (const struct ip6_hdr *) dg->network;

	dnsqr->ip_proto = dg->proto_transport;

	if (DNS_FLAG_QR(*flags) == false) {
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
dnsqr_append_response_packet(Nmsg__Isc__DnsQR *dnsqr,
			     const uint8_t *pkt, const struct pcap_pkthdr *pkt_hdr,
			     const struct timespec *ts)
{
	size_t n, idx;
	uint8_t *pkt_copy;

	n = idx = dnsqr->n_response_packet;
	n += 1;

	extend_field_array(dnsqr->response_packet);
	extend_field_array(dnsqr->response_time_sec);
	extend_field_array(dnsqr->response_time_nsec);

	pkt_copy = malloc(pkt_hdr->caplen);
	if (pkt_copy == NULL)
		return (nmsg_res_memfail);
	memcpy(pkt_copy, pkt, pkt_hdr->caplen);

	dnsqr->n_response_packet += 1;
	dnsqr->n_response_time_sec += 1;
	dnsqr->n_response_time_nsec += 1;

	dnsqr->response_packet[idx].len = pkt_hdr->caplen;
	dnsqr->response_packet[idx].data = pkt_copy;
	dnsqr->response_time_sec[idx] = ts->tv_sec;
	dnsqr->response_time_nsec[idx] = ts->tv_nsec;

	return (nmsg_res_success);
}

void
dnsqr_print_stats(dnsqr_ctx_t *ctx) {
#ifdef DEBUG
	fprintf(stderr, "%s: c= %u qr= %u uq= %u ur= %u p= %u\n", __func__,
		ctx->count,
		ctx->count_query_response,
		ctx->count_unanswered_query,
		ctx->count_unsolicited_response,
		ctx->count_packet);
	ctx->count_query_response = 0;
	ctx->count_unanswered_query = 0;
	ctx->count_unsolicited_response = 0;
#endif
}

nmsg_res
do_packet(dnsqr_ctx_t *ctx, nmsg_pcap_t pcap, nmsg_message_t *m,
	  const uint8_t *pkt, const struct pcap_pkthdr *pkt_hdr,
	  const struct timespec *ts)
{
	Nmsg__Isc__DnsQR *dnsqr = NULL;
	nmsg_res res;
	struct nmsg_ipdg dg;
	uint16_t flags;

	pthread_mutex_lock(&ctx->lock);
	ctx->now.tv_sec = ts->tv_sec;
	ctx->now.tv_nsec = ts->tv_nsec;
#ifdef DEBUG
	ctx->count_packet += 1;
	if ((ctx->count_packet % 100000) == 0)
		dnsqr_print_stats(ctx);
#endif
	pthread_mutex_unlock(&ctx->lock);

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
		res = do_packet_v4(dnsqr, &dg, &flags);
		break;
	case PF_INET6:
		res = do_packet_v6(dnsqr, &dg, &flags);
		break;
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		goto out;

	if (DNS_FLAG_QR(flags) == false) {
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

		res = dnsqr_append_response_packet(dnsqr, pkt, pkt_hdr, ts);
		if (res != nmsg_res_success)
			goto out;

		query = dnsqr_retrieve(ctx, dnsqr, DNS_FLAG_RCODE(flags));
		if (query == NULL) {
			/* no corresponding query, this is an unsolicited response */
			dnsqr->type = NMSG__ISC__DNS_QRTYPE__UDP_UNSOLICITED_RESPONSE;
			*m = dnsqr_to_message(dnsqr);
			if (*m == NULL) {
				res = nmsg_res_memfail;
				goto out;
			}
			res = nmsg_res_success;
#ifdef DEBUG
			pthread_mutex_lock(&ctx->lock);
			ctx->count_unsolicited_response += 1;
			pthread_mutex_unlock(&ctx->lock);
#endif
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
#ifdef DEBUG
			pthread_mutex_lock(&ctx->lock);
			ctx->count_query_response += 1;
			pthread_mutex_unlock(&ctx->lock);
#endif
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
	nmsg_pcap_type pcap_type;
	nmsg_res res;
	struct timespec ts;

	pcap_type = nmsg_pcap_get_type(pcap);
	if (pcap_type == nmsg_pcap_type_live) {
		nmsg_timespec_get(&ts);
	} else if (pcap_type == nmsg_pcap_type_file) {
		pthread_mutex_lock(&ctx->lock);
		memcpy(&ts, &ctx->now, sizeof(struct timespec));
		pthread_mutex_unlock(&ctx->lock);
	}

	dnsqr = dnsqr_trim(ctx, &ts);
	if (dnsqr != NULL) {
		*m = dnsqr_to_message(dnsqr);
		nmsg__isc__dns_qr__free_unpacked(dnsqr, NULL);
		return (nmsg_res_success);
	} else {
		bool stop;

		pthread_mutex_lock(&ctx->lock);
		stop = ctx->stop;
		pthread_mutex_unlock(&ctx->lock);

		if (stop == true) {
#ifdef DEBUG
			size_t count_remaining = 0;
			size_t n;
			for (n = 0; n < ctx->num_slots; n++) {
				hash_entry_t *he = &ctx->table[n];
				if (he->dnsqr != NULL)
					count_remaining += 1;
			}
			fprintf(stderr, "%s: count_remaining= %zd\n", __func__, count_remaining);
#endif
			return (nmsg_res_eof);
		}
	}

	res = nmsg_res_failure;
	while (res != nmsg_res_success) {
		struct pcap_pkthdr *pkt_hdr;
		const uint8_t *pkt_data;

		res = nmsg_pcap_input_read_raw(pcap, &pkt_hdr, &pkt_data, &ts);
		if (res == nmsg_res_success) {
			return (do_packet(ctx, pcap, m, pkt_data, pkt_hdr, &ts));
		} else if (res == nmsg_res_again) {
			continue;
		} else if (res == nmsg_res_eof) {
			pthread_mutex_lock(&ctx->lock);
			ctx->stop = true;
			pthread_mutex_unlock(&ctx->lock);
			return (nmsg_res_again);
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
