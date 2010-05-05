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

#include <pcap.h>
#include <wdns.h>

#include "ipreasm.h"
#include "lookup3.h"

#include "dnsqr.pb-c.c"

/* Macros. */

#define NUM_SLOTS	262144
#define MAX_VALUES	131072

#define QUERY_TIMEOUT	60

#define DNS_FLAG_QR(flags)	(((flags) >> 15) & 0x01)
#define DNS_FLAG_RCODE(flags)	((flags) & 0xf)

/* Data structures. */

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
	struct reasm_ip			*reasm;

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
	uint16_t			proto;
	uint16_t			query_port;
	uint16_t			response_port;
	uint16_t			id;
} dnsqr_key_t;

typedef struct {
	uint8_t				query_ip6[16];
	uint8_t				response_ip6[16];
	uint16_t			proto;
	uint16_t			query_port;
	uint16_t			response_port;
	uint16_t			id;
} dnsqr_key6_t;

typedef nmsg_res (*dnsqr_append_fp)(Nmsg__Isc__DnsQR *dnsqr,
				    const uint8_t *pkt, size_t pkt_len,
				    const struct timespec *ts);

/* Exported via module context. */

static nmsg_res dnsqr_init(void **clos);
static nmsg_res dnsqr_fini(void **clos);
static nmsg_res dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m);

static NMSG_MSGMOD_FIELD_PRINTER(dnsqr_proto_print);
static NMSG_MSGMOD_FIELD_PRINTER(dnsqr_message_print);
static NMSG_MSGMOD_FIELD_PRINTER(dnsqr_rcode_print);
static NMSG_MSGMOD_FIELD_GETTER(dnsqr_get_query);
static NMSG_MSGMOD_FIELD_GETTER(dnsqr_get_response);

/* Data. */

struct nmsg_msgmod_field dnsqr_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type"
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "query_ip"
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "response_ip"
	},
	{	.type = nmsg_msgmod_ft_uint16,
		.name = "proto",
		.print = dnsqr_proto_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "query_port"
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "response_port"
	},
	{	.type = nmsg_msgmod_ft_uint16,
		.name = "id"
	},
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
		.type = nmsg_msgmod_ft_uint16,
		.name = "rcode",
		.print = dnsqr_rcode_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "query_packet",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "query_time_sec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_int32,
		.name = "query_time_nsec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response_packet",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "response_time_sec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_int32,
		.name = "response_time_nsec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "query",
		.get = dnsqr_get_query,
		.print = dnsqr_message_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response",
		.get = dnsqr_get_response,
		.print = dnsqr_message_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "dns",
		.get = dnsqr_get_response,
		.flags = NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "tcp",
		.flags = NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "icmp",
		.flags = NMSG_MSGMOD_FIELD_NOPRINT
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
	.init = dnsqr_init,
	.fini = dnsqr_fini,
	.pkt_to_payload = dnsqr_pkt_to_payload,
};

/* Forward. */

static void dnsqr_print_stats(dnsqr_ctx_t *ctx);

/* Functions. */

static nmsg_res
dnsqr_init(void **clos) {
	dnsqr_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return (nmsg_res_memfail);

	pthread_mutex_init(&ctx->lock, NULL);

	ctx->reasm = reasm_ip_new();
	if (ctx->reasm == NULL) {
		free(ctx);
		return (nmsg_res_memfail);
	}

	ISC_LIST_INIT(ctx->list);

	ctx->num_slots = NUM_SLOTS;
	ctx->max_values = MAX_VALUES;
	ctx->len_table = sizeof(hash_entry_t) * ctx->num_slots;

	ctx->table = mmap(NULL, ctx->len_table,
			  PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	if (ctx->table == MAP_FAILED) {
		free(ctx->reasm);
		free(ctx);
		return (nmsg_res_memfail);
	}

	*clos = ctx;

	return (nmsg_res_success);
}

static nmsg_res
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

	reasm_ip_free(ctx->reasm);

	munmap(ctx->table, ctx->len_table);
	free(ctx);
	*clos = NULL;

	return (nmsg_res_success);
}

static nmsg_res
dnsqr_proto_print(nmsg_message_t msg,
		  struct nmsg_msgmod_field *field,
		  void *ptr,
		  struct nmsg_strbuf *sb,
		  const char *endline)
{
	uint16_t proto;

	proto = *((uint16_t *) ptr);

	switch (proto) {
	case IPPROTO_UDP:
		return (nmsg_strbuf_append(sb, "proto: UDP (17)\n"));
	case IPPROTO_TCP:
		return (nmsg_strbuf_append(sb, "proto: TCP (6)\n"));
	case IPPROTO_ICMP:
		return (nmsg_strbuf_append(sb, "proto: ICMP (1)\n"));
	default:
		return (nmsg_strbuf_append(sb, "proto: %hu\n", proto));
	}
}

static nmsg_res
dnsqr_message_print(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    void *ptr,
		    struct nmsg_strbuf *sb,
		    const char *endline)
{
	nmsg_res res;
	uint8_t *payload;
	size_t payload_len;

	res = nmsg_message_get_field(msg, field->name, 0, (void **) &payload, &payload_len);
	if (res == nmsg_res_success) {
		wdns_message_t dns;
		wdns_msg_status status;

		status = wdns_parse_message(&dns, payload, payload_len);
		if (status == wdns_msg_success) {
			char *s;

			s = wdns_message_to_str(&dns);
			if (s != NULL) {
				nmsg_strbuf_append(sb, "%s: [%zd octets]%s%s---%s",
						   field->name, payload_len, endline, s, endline);
				free(s);
				wdns_clear_message(&dns);
				return (nmsg_res_success);
			}
			wdns_clear_message(&dns);
		}
	}
	nmsg_strbuf_append(sb, "%s: <PARSE ERROR>%s", field->name, endline);
	return (nmsg_res_success);
}

static nmsg_res
dnsqr_rcode_print(nmsg_message_t msg,
		  struct nmsg_msgmod_field *field,
		  void *ptr,
		  struct nmsg_strbuf *sb,
		  const char *endline)
{
	const char *s;
	uint16_t *rcode = ptr;

	s = wdns_rcode_to_str(*rcode);
	return (nmsg_strbuf_append(sb, "%s: %s (%hu)%s",
				   field->name,
				   s ? s : "<UNKNOWN>",
				   *rcode, endline));
}

static nmsg_res
dnsqr_get_query(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		unsigned val_idx,
		void **data,
		size_t *len,
		void *msg_clos)
{
	Nmsg__Isc__DnsQR *dnsqr = (Nmsg__Isc__DnsQR *) nmsg_message_get_payload(msg);
	nmsg_res res;
	struct nmsg_ipdg dg;

	res = nmsg_res_failure;
	if (dnsqr == NULL || val_idx != 0 || dnsqr->n_query_packet != 1)
		return (nmsg_res_failure);

	if (dnsqr->query_ip.data != NULL) {
		if (dnsqr->query_ip.len == 4)
			res = nmsg_ipdg_parse(&dg, ETHERTYPE_IP,
					      dnsqr->query_packet[0].len,
					      dnsqr->query_packet[0].data);
		else if (dnsqr->query_ip.len == 16)
			res = nmsg_ipdg_parse(&dg, ETHERTYPE_IPV6,
					      dnsqr->query_packet[0].len,
					      dnsqr->query_packet[0].data);
	}

	if (res != nmsg_res_success)
		return (nmsg_res_failure);

	*data = (void *) dg.payload;
	if (len)
		*len = dg.len_payload;

	return (nmsg_res_success);
}

static nmsg_res
dnsqr_get_response(nmsg_message_t msg,
		   struct nmsg_msgmod_field *field,
		   unsigned val_idx,
		   void **data,
		   size_t *len,
		   void *msg_clos)
{
	Nmsg__Isc__DnsQR *dnsqr = (Nmsg__Isc__DnsQR *) nmsg_message_get_payload(msg);
	uint8_t *pkt;
	size_t pkt_len;
	nmsg_res res;
	struct nmsg_ipdg dg;

	res = nmsg_res_failure;
	if (dnsqr == NULL || val_idx != 0 || dnsqr->n_response_packet < 1)
		return (nmsg_res_failure);

	if (dnsqr->response_ip.data == NULL)
		return (nmsg_res_failure);

	if (dnsqr->n_response_packet > 1) {
		/* response is fragmented */
		enum reasm_proto proto;
		union reasm_id id;
		unsigned hash = 0;
		bool last_frag = 0;
		size_t n;
		struct timespec ts;
		struct reasm_frag_entry *frag, *list_head;
		struct reasm_ip_entry *entry;

		list_head = calloc(1, sizeof(*list_head));
		if (list_head == NULL)
			return (nmsg_res_memfail);

		entry = calloc(1, sizeof(*entry));
		if (entry == NULL) {
			free(list_head);
			return (nmsg_res_memfail);
		}

		entry->frags = list_head;
		entry->holes = 1;

		for (n = 0; n < dnsqr->n_response_packet; n++) {
			ts.tv_sec = dnsqr->response_time_sec[n];
			ts.tv_nsec = dnsqr->response_time_nsec[n];

			frag = reasm_parse_packet(dnsqr->response_packet[n].data,
						  dnsqr->response_packet[n].len,
						  &ts, &proto, &id, &hash, &last_frag);
			if (frag == NULL ||
			    reasm_add_fragment(entry, frag, last_frag) == false)
			{
				reasm_free_entry(entry);
				return (nmsg_res_memfail);
			}
		}
		if (reasm_is_complete(entry)) {
			pkt_len = NMSG_IPSZ_MAX;
			pkt = malloc(NMSG_IPSZ_MAX);
			if (pkt == NULL) {
				reasm_free_entry(entry);
				return (nmsg_res_memfail);
			}
			res = nmsg_message_add_allocation(msg, pkt);
			if (res != nmsg_res_success) {
				free(pkt);
				reasm_free_entry(entry);
				return (nmsg_res_memfail);
			}

			reasm_assemble(entry, pkt, &pkt_len);
			if (pkt_len == 0) {
				free(pkt);
				reasm_free_entry(entry);
				return (nmsg_res_failure);
			}

			if (proto == PROTO_IPV4) {
				res = nmsg_ipdg_parse(&dg, ETHERTYPE_IP, pkt_len, pkt);
			} else if (proto == PROTO_IPV6) {
				res = nmsg_ipdg_parse(&dg, ETHERTYPE_IPV6, pkt_len, pkt);
			} else {
				assert(0);
			}

			reasm_free_entry(entry);
		} else {
			reasm_free_entry(entry);
			return (nmsg_res_failure);
		}

	} else {
		pkt = dnsqr->response_packet[0].data;
		pkt_len = dnsqr->response_packet[0].len;
		if (dnsqr->response_ip.len == 4)
			res = nmsg_ipdg_parse(&dg, ETHERTYPE_IP, pkt_len, pkt);
		else if (dnsqr->response_ip.len == 16)
			res = nmsg_ipdg_parse(&dg, ETHERTYPE_IPV6, pkt_len, pkt);
	}

	if (res != nmsg_res_success)
		return (nmsg_res_failure);

	*data = (void *) dg.payload;
	if (len)
		*len = dg.len_payload;

	return (nmsg_res_success);
}

static bool
dnsqr_eq6(Nmsg__Isc__DnsQR *d1, Nmsg__Isc__DnsQR *d2) {
	if (d1->id == d2->id &&
	    d1->query_port == d2->query_port &&
	    d1->response_port == d2->response_port &&
	    d1->proto == d2->proto &&
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

static bool
dnsqr_eq9(Nmsg__Isc__DnsQR *d1, Nmsg__Isc__DnsQR *d2) {
	if (d1->id == d2->id &&
	    d1->query_port == d2->query_port &&
	    d1->response_port == d2->response_port &&
	    d1->qname.len == d2->qname.len &&
	    d1->qtype == d2->qtype &&
	    d1->qclass == d2->qclass &&
	    d1->proto == d2->proto &&
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

static bool
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

static uint32_t
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
		key.proto = dnsqr->proto;
		key.query_port = dnsqr->query_port;
		key.response_port = dnsqr->response_port;
		key.id = dnsqr->id;
		k = &key;
		len = sizeof(key);
	} else if (dnsqr->query_ip.len == 16) {
		memcpy(&key6.query_ip6, dnsqr->query_ip.data, 16);
		memcpy(&key6.response_ip6, dnsqr->response_ip.data, 16);
		key6.proto = dnsqr->proto;
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

static void
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

static void
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

static Nmsg__Isc__DnsQR *
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
#ifdef DEBUG
			ctx->count_unanswered_query += 1;
#endif
		}
	}

	/* unlock hash table */
	pthread_mutex_unlock(&ctx->lock);

	return (dnsqr);
}

static Nmsg__Isc__DnsQR *
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

static nmsg_message_t
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

static nmsg_res
do_packet_dns(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const uint8_t *p;
	size_t len;
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

		if (len < 4)
			return (nmsg_res_again);

		memcpy(dnsqr->qname.data, p, dnsqr->qname.len);
		dnsqr->has_qname = true;
		p += dnsqr->qname.len;

		memcpy(&qtype, p, 2);
		p += 2;
		memcpy(&qclass, p, 2);
		p += 2;

		dnsqr->qtype = ntohs(qtype);
		dnsqr->has_qtype = true;
		dnsqr->qclass = ntohs(qclass);
		dnsqr->has_qclass = true;
	}

	return (nmsg_res_success);
}

static nmsg_res
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

static nmsg_res
do_packet_tcp(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const struct tcphdr *tcp;
	nmsg_res res;
	uint16_t src_port;
	uint16_t dst_port;

	tcp = (const struct tcphdr *) dg->transport;
	src_port = ntohs(tcp->th_sport);
	dst_port = ntohs(tcp->th_dport);

	if (!(src_port == 53 || dst_port == 53))
		return (nmsg_res_again);

	dnsqr->tcp.data = malloc(dg->len_network);
	if (dnsqr->tcp.data == NULL)
		return (nmsg_res_memfail);
	memcpy(dnsqr->tcp.data, dg->network, dg->len_network);
	dnsqr->tcp.len = dg->len_network;
	dnsqr->has_tcp = true;

	dnsqr->type = NMSG__ISC__DNS_QRTYPE__TCP;

	return (nmsg_res_success);
}

static nmsg_res
do_packet_icmp(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	struct nmsg_ipdg icmp_dg;
	nmsg_res res;
	uint16_t src_port;
	uint16_t dst_port;

	res = nmsg_ipdg_parse_pcap_raw(&icmp_dg, DLT_RAW, dg->payload, dg->len_payload);
	if (res != nmsg_res_success)
		return (res);
	if (icmp_dg.proto_transport == IPPROTO_UDP) {
		const struct udphdr *udp;

		udp = (const struct udphdr *) icmp_dg.transport;
		src_port = ntohs(udp->uh_sport);
		dst_port = ntohs(udp->uh_dport);

		if (!(src_port == 53 || src_port == 5353 || dst_port == 53 || dst_port == 5353))
			return (nmsg_res_again);
	} else if (icmp_dg.proto_transport == IPPROTO_TCP) {
		const struct tcphdr *tcp;

		tcp = (const struct tcphdr *) icmp_dg.transport;
		src_port = ntohs(tcp->th_sport);
		dst_port = ntohs(tcp->th_dport);

		if (!(src_port == 53 || dst_port == 53))
			return (nmsg_res_again);
	} else {
		return (nmsg_res_again);
	}

	dnsqr->icmp.data = malloc(dg->len_network);
	if (dnsqr->icmp.data == NULL)
		return (nmsg_res_memfail);
	memcpy(dnsqr->icmp.data, dg->network, dg->len_network);
	dnsqr->icmp.len = dg->len_network;
	dnsqr->has_icmp = true;

	dnsqr->type = NMSG__ISC__DNS_QRTYPE__ICMP;

	return (nmsg_res_success);
}

static nmsg_res
do_packet_v4(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const struct ip *ip;
	nmsg_res res;
	uint32_t ip4;

	switch (dg->proto_transport) {
	case IPPROTO_UDP:
		res = do_packet_udp(dnsqr, dg, flags);
		break;
	case IPPROTO_TCP:
		return (do_packet_tcp(dnsqr, dg, flags));
	case IPPROTO_ICMP:
		return (do_packet_icmp(dnsqr, dg, flags));
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		return (res);

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

	ip = (const struct ip *) dg->network;

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

static nmsg_res
do_packet_v6(Nmsg__Isc__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const struct ip6_hdr *ip6;
	nmsg_res res;

	switch (dg->proto_transport) {
	case IPPROTO_UDP:
		res = do_packet_udp(dnsqr, dg, flags);
		break;
	case IPPROTO_TCP:
		return (do_packet_tcp(dnsqr, dg, flags));
	case IPPROTO_ICMP:
		return (do_packet_icmp(dnsqr, dg, flags));
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		return (res);

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

	ip6 = (const struct ip6_hdr *) dg->network;

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

static void
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

	if (d2->has_qname == false && d1->has_qname == true) {
		memcpy(&d2->qname, &d1->qname, sizeof(ProtobufCBinaryData));
		memset(&d1->qname, 0, sizeof(ProtobufCBinaryData));
		d2->has_qname = true;
	}
	if (d2->has_qtype == false && d1->has_qtype == true) {
		d2->qtype = d1->qtype;
		d2->has_qtype = true;
	}
	if (d2->has_qclass == false && d1->has_qclass == true) {
		d2->qclass = d1->qclass;
		d2->has_qclass = true;
	}

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

static nmsg_res
dnsqr_append_query_packet(Nmsg__Isc__DnsQR *dnsqr,
			  const uint8_t *pkt, size_t pkt_len,
			  const struct timespec *ts)
{
	size_t n, idx;
	uint8_t *pkt_copy;

	n = idx = dnsqr->n_query_packet;
	n += 1;

	extend_field_array(dnsqr->query_packet);
	extend_field_array(dnsqr->query_time_sec);
	extend_field_array(dnsqr->query_time_nsec);

	pkt_copy = malloc(pkt_len);
	if (pkt_copy == NULL)
		return (nmsg_res_memfail);
	memcpy(pkt_copy, pkt, pkt_len);

	dnsqr->n_query_packet += 1;
	dnsqr->n_query_time_sec += 1;
	dnsqr->n_query_time_nsec += 1;

	dnsqr->query_packet[idx].len = pkt_len;
	dnsqr->query_packet[idx].data = pkt_copy;
	dnsqr->query_time_sec[idx] = ts->tv_sec;
	dnsqr->query_time_nsec[idx] = ts->tv_nsec;

	return (nmsg_res_success);
}

static nmsg_res
dnsqr_append_response_packet(Nmsg__Isc__DnsQR *dnsqr,
			     const uint8_t *pkt, size_t pkt_len,
			     const struct timespec *ts)
{
	size_t n, idx;
	uint8_t *pkt_copy;

	n = idx = dnsqr->n_response_packet;
	n += 1;

	extend_field_array(dnsqr->response_packet);
	extend_field_array(dnsqr->response_time_sec);
	extend_field_array(dnsqr->response_time_nsec);

	pkt_copy = malloc(pkt_len);
	if (pkt_copy == NULL)
		return (nmsg_res_memfail);
	memcpy(pkt_copy, pkt, pkt_len);

	dnsqr->n_response_packet += 1;
	dnsqr->n_response_time_sec += 1;
	dnsqr->n_response_time_nsec += 1;

	dnsqr->response_packet[idx].len = pkt_len;
	dnsqr->response_packet[idx].data = pkt_copy;
	dnsqr->response_time_sec[idx] = ts->tv_sec;
	dnsqr->response_time_nsec[idx] = ts->tv_nsec;

	return (nmsg_res_success);
}

static nmsg_res
dnsqr_append_frag(dnsqr_append_fp func,
		  Nmsg__Isc__DnsQR *dnsqr,
		  struct reasm_ip_entry *entry)
{
	nmsg_res res;
	struct reasm_frag_entry *frag = entry->frags->next;

	while (frag != NULL) {
		res = func(dnsqr, frag->data, frag->len + frag->data_offset, &frag->ts);
		if (res != nmsg_res_success)
			return (res);
		frag = frag->next;
	}
	return (nmsg_res_success);
}

static void
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

static nmsg_res
do_packet(dnsqr_ctx_t *ctx, nmsg_pcap_t pcap, nmsg_message_t *m,
	  const uint8_t *pkt, const struct pcap_pkthdr *pkt_hdr,
	  const struct timespec *ts)
{
	Nmsg__Isc__DnsQR *dnsqr = NULL;
	bool is_frag;
	nmsg_res res;
	struct nmsg_ipdg dg;
	struct reasm_ip_entry *reasm_entry = NULL;
	uint16_t flags;
	uint8_t *new_pkt = NULL;
	size_t new_pkt_len;

	/* only operate on complete packets */
	if (pkt_hdr->caplen != pkt_hdr->len)
		return (nmsg_res_again);

	res = nmsg_ipdg_parse_pcap_raw(&dg, nmsg_pcap_get_datalink(pcap), pkt, pkt_hdr->caplen);
	if (res != nmsg_res_success)
		return (res);

	pthread_mutex_lock(&ctx->lock);
	ctx->now.tv_sec = ts->tv_sec;
	ctx->now.tv_nsec = ts->tv_nsec;
#ifdef DEBUG
	ctx->count_packet += 1;
	if ((ctx->count_packet % 100000) == 0)
		dnsqr_print_stats(ctx);
#endif
	is_frag = reasm_ip_next(ctx->reasm, dg.network, dg.len_network, ts, &reasm_entry);
	pthread_mutex_unlock(&ctx->lock);

	if (is_frag) {
		if (reasm_entry != NULL) {
			new_pkt_len = NMSG_IPSZ_MAX;
			new_pkt = malloc(NMSG_IPSZ_MAX);
			if (new_pkt == NULL)
				return (nmsg_res_memfail);
			reasm_assemble(reasm_entry, new_pkt, &new_pkt_len);
			res = nmsg_ipdg_parse_pcap_raw(&dg, DLT_RAW, new_pkt, new_pkt_len);
			if (res != nmsg_res_success)
				goto out;
			if (nmsg_pcap_filter(pcap, dg.network, dg.len_network) == false) {
				res = nmsg_res_again;
				goto out;
			}
		} else {
			return (nmsg_res_again);
		}
	}

	dnsqr = calloc(1, sizeof(*dnsqr));
	if (dnsqr == NULL) {
		res = nmsg_res_memfail;
		goto out;
	}
	nmsg__isc__dns_qr__init(dnsqr);

	dnsqr->proto = dg.proto_transport;

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

	if (dg.proto_transport == IPPROTO_UDP && DNS_FLAG_QR(flags) == false) {
		/* message is a query */
		dnsqr->type = NMSG__ISC__DNS_QRTYPE__UDP_UNANSWERED_QUERY;
		if (is_frag)
			res = dnsqr_append_frag(dnsqr_append_query_packet, dnsqr, reasm_entry);
		else
			res = dnsqr_append_query_packet(dnsqr, dg.network, dg.len_network, ts);
		if (res != nmsg_res_success)
			goto out;
		dnsqr_insert_query(ctx, dnsqr);
		dnsqr = NULL;
		res = nmsg_res_again;
	} else if (dg.proto_transport == IPPROTO_UDP) {
		/* message is a response */
		Nmsg__Isc__DnsQR *query;

		dnsqr->rcode = DNS_FLAG_RCODE(flags);
		dnsqr->has_rcode = true;

		if (is_frag)
			res = dnsqr_append_frag(dnsqr_append_response_packet, dnsqr, reasm_entry);
		else
			res = dnsqr_append_response_packet(dnsqr, dg.network, dg.len_network, ts);
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
	} else if (dg.proto_transport == IPPROTO_TCP ||
		   dg.proto_transport == IPPROTO_ICMP)
	{
		*m = dnsqr_to_message(dnsqr);
		if (*m == NULL) {
			res = nmsg_res_memfail;
			goto out;
		}
		nmsg_message_set_time(*m, ts);
	}

out:
	if (dnsqr != NULL)
		nmsg__isc__dns_qr__free_unpacked(dnsqr, NULL);
	if (new_pkt != NULL)
		free(new_pkt);
	if (reasm_entry != NULL)
		reasm_free_entry(reasm_entry);
	return (res);
}

static nmsg_res
dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m) {
	Nmsg__Isc__DnsQR *dnsqr;
	dnsqr_ctx_t *ctx = (dnsqr_ctx_t *) clos;
	nmsg_pcap_type pcap_type;
	nmsg_res res;
	struct timespec ts;
	struct pcap_pkthdr *pkt_hdr;
	const uint8_t *pkt_data;

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

		if (stop == true)
			return (nmsg_res_eof);
	}

	res = nmsg_pcap_input_read_raw(pcap, &pkt_hdr, &pkt_data, &ts);
	if (res == nmsg_res_success) {
		return (do_packet(ctx, pcap, m, pkt_data, pkt_hdr, &ts));
	} else if (res == nmsg_res_eof) {
		pthread_mutex_lock(&ctx->lock);
		ctx->stop = true;
		pthread_mutex_unlock(&ctx->lock);
		return (nmsg_res_again);
	}

	return (res);
}
