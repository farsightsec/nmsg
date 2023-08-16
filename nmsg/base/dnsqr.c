/* dnsqr nmsg message module */

/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2010-2016, 2018, 2019, 2021 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>
#include <wdns.h>
#include <errno.h>

#include "ipreasm.h"
#include "nmsg_json.h"

#include "dnsqr.pb-c.h"

#include "libmy/list.h"
#include "libmy/lookup3.h"
#include "libmy/my_alloc.h"
#include "libmy/string_replace.h"
#include "libmy/ubuf.h"

/* Macros. */

#define DEFAULT_NUM_SLOTS	262144
#define DEFAULT_MAX_VALUES	131072
#define DEFAULT_QUERY_TIMEOUT	60

#define DNS_FLAG_QR(flags)	(((flags) >> 15) & 0x01)
#define DNS_FLAG_RD(flags)	(((flags) >> 8) & 0x01)
#define DNS_FLAG_RCODE(flags)	((flags) & 0xf)

/* Data structures. */

typedef struct list_entry list_entry_t;
typedef struct hash_entry hash_entry_t;

struct list_entry {
	ISC_LINK(struct list_entry)	link;
	hash_entry_t			*he;
};

struct hash_entry {
	Nmsg__Base__DnsQR		*dnsqr;
	list_entry_t			*le;
};

typedef struct {
	pthread_mutex_t			lock;

	hash_entry_t			*table;
	ISC_LIST(struct list_entry)	list;
	struct reasm_ip			*reasm;

	size_t				len_table;

	bool				stop;
	int				capture_qr;
	int				capture_rd;
	bool				zero_resolver_address;

	uint32_t			num_slots;
	uint32_t			max_values;
	uint32_t			query_timeout;
	uint32_t			count;
#ifdef DEBUG
	uint32_t			count_unanswered_query;
	uint32_t			count_unsolicited_response;
	uint32_t			count_query_response;
	uint32_t			count_packet;
#endif
	struct timespec			now;

	wdns_name_t			**filter_qnames_exclude;
	uint32_t			filter_qnames_exclude_slots;

	wdns_name_t			**filter_qnames_include;
	uint32_t			filter_qnames_include_slots;
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

typedef struct {
	uint8_t				src[4];
	uint8_t				dst[4];
	uint8_t				zero;
	uint8_t				proto;
	uint16_t			udp_len;
	uint16_t			src_port;
	uint16_t			dst_port;
	uint16_t			length;
	uint16_t			checksum;
} __attribute__((__packed__)) udp_pseudo_ipv4;

typedef struct {
	uint8_t				src[16];
	uint8_t				dst[16];
	uint32_t			upper_len;
	uint8_t				zero[3];
	uint8_t				next;
	uint16_t			src_port;
	uint16_t			dst_port;
	uint16_t			length;
	uint16_t			checksum;
} __attribute__((__packed__)) udp_pseudo_ipv6;

typedef nmsg_res (*dnsqr_append_fp)(Nmsg__Base__DnsQR *dnsqr,
				    const uint8_t *pkt, size_t pkt_len,
				    const struct timespec *ts);

/* Exported via module context. */

static nmsg_res dnsqr_init(void **clos);
static nmsg_res dnsqr_fini(void **clos);
static nmsg_res dnsqr_pcap_init(void *clos, nmsg_pcap_t pcap);
static nmsg_res dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m);

static NMSG_MSGMOD_FIELD_PRINTER(dnsqr_proto_print);
static NMSG_MSGMOD_FIELD_PRINTER(dnsqr_message_print);
static NMSG_MSGMOD_FIELD_PRINTER(dnsqr_rcode_print);

static NMSG_MSGMOD_FIELD_FORMATTER(dnsqr_proto_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dnsqr_message_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dnsqr_rcode_format);

static NMSG_MSGMOD_FIELD_PARSER(dnsqr_proto_parse);
static NMSG_MSGMOD_FIELD_PARSER(dnsqr_rcode_parse);

static NMSG_MSGMOD_FIELD_GETTER(dnsqr_get_delay);
static NMSG_MSGMOD_FIELD_GETTER(dnsqr_get_query);
static NMSG_MSGMOD_FIELD_GETTER(dnsqr_get_response);
static NMSG_MSGMOD_FIELD_GETTER(dnsqr_get_udp_checksum);

/* Data. */

struct nmsg_msgmod_field dnsqr_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type",
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "query_ip",
	},
	{
		.type = nmsg_msgmod_ft_ip,
		.name = "response_ip",
	},
	{	.type = nmsg_msgmod_ft_uint16,
		.name = "proto",
		.print = dnsqr_proto_print,
		.format = dnsqr_proto_format,
		.parse = dnsqr_proto_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "query_port",
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "response_port",
	},
	{	.type = nmsg_msgmod_ft_uint16,
		.name = "id",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "qname",
		.print = dns_name_print,
		.format = dns_name_format,
		.parse = dns_name_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qclass",
		.print = dns_class_print,
		.format = dns_class_format,
		.parse = dns_class_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qtype",
		.print = dns_type_print,
		.format = dns_type_format,
		.parse = dns_type_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rcode",
		.print = dnsqr_rcode_print,
		.format = dnsqr_rcode_format,
		.parse = dnsqr_rcode_parse,
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "query_packet",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "query_time_sec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_int32,
		.name = "query_time_nsec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response_packet",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_int64,
		.name = "response_time_sec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_int32,
		.name = "response_time_nsec",
		.flags = NMSG_MSGMOD_FIELD_REPEATED | NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_double,
		.name = "timeout",
	},
	{
		.type = nmsg_msgmod_ft_double,
		.name = "delay",
		.get = dnsqr_get_delay,
	},
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "udp_checksum",
		.get = dnsqr_get_udp_checksum,
	},
	{
		.type = nmsg_msgmod_ft_bool,
		.name = "resolver_address_zeroed",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "query",
		.get = dnsqr_get_query,
		.print = dnsqr_message_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "query_json",
		.get = dnsqr_get_query,
		.format = dnsqr_message_format,
		.flags = NMSG_MSGMOD_FIELD_FORMAT_RAW | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response",
		.get = dnsqr_get_response,
		.print = dnsqr_message_print
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "response_json",
		.get = dnsqr_get_response,
		.format = dnsqr_message_format,
		.flags = NMSG_MSGMOD_FIELD_FORMAT_RAW | NMSG_MSGMOD_FIELD_NOPRINT
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "dns",
		.get = dnsqr_get_response,
		.flags = NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "tcp",
		.flags = NMSG_MSGMOD_FIELD_NOPRINT,
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "icmp",
		.flags = NMSG_MSGMOD_FIELD_NOPRINT,
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor = NMSG_VENDOR_BASE,
	.msgtype = { NMSG_VENDOR_BASE_DNSQR_ID, NMSG_VENDOR_BASE_DNSQR_NAME },

	.pbdescr = &nmsg__base__dns_qr__descriptor,
	.fields = dnsqr_fields,
	.init = dnsqr_init,
	.fini = dnsqr_fini,
	.pkt_to_payload = dnsqr_pkt_to_payload,
	.pcap_init = dnsqr_pcap_init,
};

/* Forward. */

static void dnsqr_print_stats(dnsqr_ctx_t *ctx);

/* Functions. */

static int
dnsqr_checksum_verify(Nmsg__Base__DnsQR *dnsqr) {
	nmsg_res res;
	size_t ip_len;
	struct nmsg_ipdg dg;
	struct nmsg_iphdr *ip;
	struct nmsg_udphdr *udp;
	uint16_t word;
	uint32_t sum = 0;
	uint8_t *p = NULL;
	udp_pseudo_ipv4 ph;
	udp_pseudo_ipv6 ph6;
	size_t pseudo_len = 0;

	/* if the resolver address was zeroed, it's now impossible to
	 * verify the checksum */
	if (dnsqr->has_resolver_address_zeroed &&
	    dnsqr->resolver_address_zeroed)
	{
		return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ERROR);
	}

	/* locate the initial fragment and create the pseudo header */
	for (unsigned r = 0; r < dnsqr->n_response_packet; r++) {
		uint8_t *data = NULL;
		ssize_t data_len = 0;

		ip = (struct nmsg_iphdr *) dnsqr->response_packet[r].data;
		ip_len = dnsqr->response_packet[r].len;

		res = nmsg_ipdg_parse_pcap_raw(&dg, DLT_RAW, (uint8_t *) ip, ip_len);
		if (res != nmsg_res_success)
			return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ERROR);

		if (dg.proto_network == PF_INET && dg.proto_transport == IPPROTO_UDP) {
			data = (uint8_t *) dg.payload;
			data_len = dg.len_payload;

			if (dg.transport != NULL) {
				/* this is the initial fragment */
				if (dg.len_transport < sizeof(struct nmsg_udphdr))
					return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ERROR);

				p = (uint8_t *) &ph;
				pseudo_len = sizeof(ph);
				memset(&ph, 0, sizeof(ph));
				udp = (struct nmsg_udphdr *) (dg.transport);

				if (udp->uh_sum == 0)
					return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ABSENT);

				/* create the IPv4 UDP pseudo header */
				memcpy(&ph.src[0],	&ip->ip_src,	4);
				memcpy(&ph.dst[0],	&ip->ip_dst,	4);
				memcpy(&ph.proto,	&ip->ip_p,	1);
				memcpy(&ph.udp_len,	&udp->uh_ulen,	2);
				memcpy(&ph.src_port,	&udp->uh_sport,	2);
				memcpy(&ph.dst_port,	&udp->uh_dport,	2);
				memcpy(&ph.length,	&udp->uh_ulen,	2);
				memcpy(&ph.checksum,	&udp->uh_sum,	2);
			}
		} else if (dg.proto_network == PF_INET6 && dg.proto_transport == IPPROTO_UDP) {
			data = (uint8_t *) dg.payload;
			data_len = dg.len_payload;

			if (dg.transport != NULL) {
				/* this is the initial fragment */
				if (dg.len_transport < sizeof(struct nmsg_udphdr))
					return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ERROR);

				p = (uint8_t *) &ph6;
				pseudo_len = sizeof(ph6);
				udp = (struct nmsg_udphdr *) (dg.transport);
				struct ip6_hdr *ip6 = (struct ip6_hdr *) (dg.network);
				memset(&ph6, 0, sizeof(ph6));

				if (udp->uh_sum == 0)
					return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ABSENT);

				/* create the IPv6 UDP pseudo header */
				memcpy(&ph6.src[0],	&ip6->ip6_src,	16);
				memcpy(&ph6.dst[0],	&ip6->ip6_dst,	16);
				memcpy(&ph6.src_port,	&udp->uh_sport,	2);
				memcpy(&ph6.dst_port,	&udp->uh_dport,	2);
				memcpy(&ph6.length,	&udp->uh_ulen,	2);
				memcpy(&ph6.checksum,	&udp->uh_sum,	2);

				memcpy(&word, &udp->uh_ulen, 2);
				ph6.upper_len = (uint32_t) word;
				ph6.next = IPPROTO_UDP;
			}
		} else {
			return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ERROR);
		}

		if (data_len < 0)
			return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ERROR);

		/* sum the payload, less the last octet if an odd number of octets */
		for (int i = 0; i < data_len - 1; i += 2) {
			memcpy(&word, data + i, 2);
			sum += ntohs(word);
		}

		/* sum the last octet of the payload if necessary */
		if ((data_len & 1) == 1) {
			word = (data[data_len - 1] << 8) & 0xff00;
			sum += word;
		}
	}

	/* if p was not set, the initial fragment was not found
	 * (and thus the pseudo header could not be created) */
	if (p == NULL)
		return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__ERROR);

	/* sum the pseudo header */
	for (int i = 0; i < (ssize_t) pseudo_len; i += 2) {
		memcpy(&word, p + i, 2);
		sum += ntohs(word);
	}

	/* accumulate the 32 bit sum into 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = (uint16_t) ~sum;

	/* check if checksum is correct */
	if (sum == 0)
		return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__CORRECT);
	return (NMSG__BASE__DNS_QR__UDP_CHECKSUM__INCORRECT);
}

static void
dnsqr_zero_resolver_address(Nmsg__Base__DnsQR *dnsqr) {
	struct nmsg_iphdr *ip;
	struct ip6_hdr *ip6;
	size_t ip_len;

	if (dnsqr->n_query_packet > 0 || dnsqr->n_response_packet > 0) {
		dnsqr->resolver_address_zeroed = true;
		dnsqr->has_resolver_address_zeroed = true;
	}

	/* zero the protobuf query_ip field */
	memset(dnsqr->query_ip.data, 0, dnsqr->query_ip.len);

	/* zero the query */
	for (unsigned i = 0; i < dnsqr->n_query_packet; i++) {
		ip = (struct nmsg_iphdr *) dnsqr->query_packet[i].data;
		ip_len = dnsqr->query_packet[i].len;

		if (ip->ip_v == 4) {
			if (ip_len >= sizeof(struct nmsg_iphdr))
				memset(&ip->ip_src, 0, 4);
		} else if (ip->ip_v == 6) {
			/* Avoid compiler align warning from direct ref to ip */
			ip6 = (struct ip6_hdr *) dnsqr->query_packet[i].data;
			if (ip_len >= sizeof(struct ip6_hdr))
				memset(&ip6->ip6_src, 0, 16);
		}
	}

	/* zero the response */
	for (unsigned i = 0; i < dnsqr->n_response_packet; i++) {
		ip = (struct nmsg_iphdr *) dnsqr->response_packet[i].data;
		ip_len = dnsqr->response_packet[i].len;

		if (ip->ip_v == 4) {
			if (ip_len >= sizeof(struct nmsg_iphdr))
				memset(&ip->ip_dst, 0, 4);
		} else if (ip->ip_v == 6) {
			/* Avoid compiler align warning from direct ref to ip */
			ip6 = (struct ip6_hdr *) dnsqr->query_packet[i].data;
			if (ip_len >= sizeof(struct ip6_hdr))
				memset(&ip6->ip6_dst, 0, 16);
		}
	}
}

static bool
getenv_int(const char *name, int64_t *value) {
	char *s, *t;

	s = getenv(name);
	if (s == NULL)
		return (false);

	*value = strtol(s, &t, 0);
	if (*t != '\0')
		return (false);
	return (true);
}

static bool
dnsqr_filter_lookup(wdns_name_t **table, uint32_t num_slots, wdns_name_t *name) {
	unsigned slot, slot_stop;

	slot = my_hashlittle(name->data, name->len, 0) % num_slots;
	if (slot > 0)
		slot_stop = slot - 1;
	else
		slot_stop = num_slots - 1;

	for (;;) {
		wdns_name_t *ent = table[slot];

		/* empty slot, not present */
		if (ent == NULL)
			return (false);

		/* hit */
		if (ent != NULL &&
		    ent->len == name->len &&
		    memcmp(ent->data, name->data, name->len) == 0)
		{
			return (true);
		}

		/* slot filled, but not our value */
		assert(slot != slot_stop);
		slot += 1;
		if (slot >= num_slots)
			slot = 0;
	}
}

static void
dnsqr_filter_insert(wdns_name_t **table, uint32_t num_slots, wdns_name_t *name) {
	unsigned slot, slot_stop;
	wdns_name_t **ent;

	slot = my_hashlittle(name->data, name->len, 0) % num_slots;
	if (slot > 0)
		slot_stop = slot - 1;
	else
		slot_stop = num_slots - 1;

	for (;;) {
		ent = &table[slot];

		/* empty slot, insert */
		if (*ent == NULL) {
			*ent = name;
			break;
		}

		/* slot filled */
		assert(slot != slot_stop);
		slot += 1;
		if (slot >= num_slots)
			slot = 0;
	}
}

static void
dnsqr_filter_init(const char *env_var, wdns_name_t ***table, uint32_t *num_slots) {
	char *names, *saveptr, *token;
	uint32_t num_names;
	unsigned i;

	if (getenv(env_var) == NULL)
		return;

	num_names = 1;

	names = strdup(getenv(env_var));
	assert(names != NULL);

	for (i = 0; i < strlen(names); i++) {
		if (names[i] == ':')
			num_names += 1;
	}

	*num_slots = num_names * 2;

	*table = my_calloc(1, sizeof(void *) * *num_slots);

	token = strtok_r(names, ":", &saveptr);
	do {
		wdns_res res;
		wdns_name_t *name;

		name = my_malloc(sizeof(*name));
		res = wdns_str_to_name(token, name);
		if (res == wdns_res_success) {
			wdns_downcase_name(name);
			dnsqr_filter_insert(*table, *num_slots, name);
		} else {
			if (nmsg_get_debug() >= 1)
				fprintf(stderr,
					"%s: wdns_str_to_name() failed, token='%s' res=%d\n",
					__func__, token, res);
		}

	} while ((token = strtok_r(NULL, ":", &saveptr)) != NULL);

	free(names);
}

static void
dnsqr_filter_destroy(wdns_name_t **table, uint32_t num_slots) {
	unsigned i;

	for (i = 0; i < num_slots; i++) {
		if (table[i] != NULL) {
			free(table[i]->data);
			free(table[i]);
			table[i] = NULL;
		}
	}
}

static nmsg_res
dnsqr_init(void **clos) {
	dnsqr_ctx_t *ctx;
	int64_t qr, rd, max, timeout, zero;

	ctx = my_calloc(1, sizeof(*ctx));
	pthread_mutex_init(&ctx->lock, NULL);

	ctx->reasm = reasm_ip_new();
	assert(ctx->reasm != NULL);

	ISC_LIST_INIT(ctx->list);

	if (getenv_int("DNSQR_CAPTURE_QR", &qr) &&
	    (qr == 0 || qr == 1))
	{
		ctx->capture_qr = qr;
	} else {
		ctx->capture_qr = -1;
	}

	if (getenv_int("DNSQR_CAPTURE_RD", &rd) &&
	    (rd == 0 || rd == 1))
	{
		ctx->capture_rd = rd;
	} else {
		ctx->capture_rd = -1;
	}

	if (getenv_int("DNSQR_ZERO_RESOLVER_ADDRESS", &zero) && zero)
		ctx->zero_resolver_address = true;

	if (getenv_int("DNSQR_STATE_TABLE_MAX", &max) && max > 0) {
		ctx->max_values = max;
		ctx->num_slots = ctx->max_values * 2;
	} else {
		ctx->num_slots = DEFAULT_NUM_SLOTS;
		ctx->max_values = DEFAULT_MAX_VALUES;
	}

	if (getenv_int("DNSQR_QUERY_TIMEOUT", &timeout) && timeout > 0)
		ctx->query_timeout = timeout;
	else
		ctx->query_timeout = DEFAULT_QUERY_TIMEOUT;

	dnsqr_filter_init("DNSQR_FILTER_QNAMES_INCLUDE",
			  &ctx->filter_qnames_include,
			  &ctx->filter_qnames_include_slots);
	dnsqr_filter_init("DNSQR_FILTER_QNAMES_EXCLUDE",
			  &ctx->filter_qnames_exclude,
			  &ctx->filter_qnames_exclude_slots);

	ctx->len_table = sizeof(hash_entry_t) * ctx->num_slots;

	ctx->table = mmap(NULL, ctx->len_table,
			  PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	assert(ctx->table != MAP_FAILED);

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
			nmsg__base__dns_qr__free_unpacked(he->dnsqr, NULL);
	}

	dnsqr_filter_destroy(ctx->filter_qnames_include, ctx->filter_qnames_include_slots);
	dnsqr_filter_destroy(ctx->filter_qnames_exclude, ctx->filter_qnames_exclude_slots);

	dnsqr_print_stats(ctx);

	reasm_ip_free(ctx->reasm);

	munmap(ctx->table, ctx->len_table);
	free(ctx);
	*clos = NULL;

	return (nmsg_res_success);
}

static int
get_af(const char *addr) {
	char *s, *slash;
	char buf[16];
	int af;

	s = strdup(addr);
	assert(s != NULL);
	slash = strchr(s, '/');
	if (slash != NULL)
		*slash = '\x00';
	if (inet_pton(AF_INET, s, buf) == 1) {
		af = AF_INET;
	} else if (inet_pton(AF_INET6, s, buf) == 1) {
		af = AF_INET6;
	} else {
		af = -1;
	}
	free(s);
	return (af);
}

static char *
addrs_to_bpf(const char *addrs, const char *bpfdir, int af) {
	char *ret, *tok_addrs, *addr, *saveptr;
	size_t retsz;
	int addr_af;
	ubuf *bpf;

	bpf = ubuf_new();
	tok_addrs = strdup(addrs);
	assert(tok_addrs != NULL);

	addr = strtok_r(tok_addrs, ",", &saveptr);
	do {
		/* strip leading spaces */
		while (isspace(addr[0]))
			addr++;
		/* strip trailing spaces */
		size_t i = strlen(addr);
		while (i--) {
			if (isspace(addr[i]))
				addr[i] = '\x00';
			else
				break;
		}

		addr_af = get_af(addr);
		if (addr_af != af)
			continue;
		if (addr_af != AF_INET && addr_af != AF_INET6) {
			ubuf_destroy(&bpf);
			free(tok_addrs);
			return (NULL);
		}

		if (ubuf_size(bpf) > 0)
			ubuf_add_cstr(bpf, " or ");
		ubuf_add_cstr(bpf, bpfdir);
		ubuf_add_cstr(bpf, " ");
		if (strchr(addr, '/') != NULL)
			ubuf_add_cstr(bpf, "net ");
		ubuf_add_cstr(bpf, addr);
	} while ((addr = strtok_r(NULL, ",", &saveptr)) != NULL);

	free(tok_addrs);
	ubuf_cterm(bpf);
	ubuf_detach(bpf, (uint8_t **) &ret, &retsz);
	ubuf_destroy(&bpf);
	return (ret);
}

#define ipv4_frags	"(ip[6:2] & 0x3fff != 0)"
#define udp_qr_query	"(((udp[10:2] >> 15) & 0x01) == 0)"
#define udp_qr_response	"(((udp[10:2] >> 15) & 0x01) == 1)"

static const char *s_pattern_auth4 =
	"("
	"((@DST@) and udp dst port 53) or "
	"((@SRC@) and udp src port 53) or "
	"((@SRC@) and " ipv4_frags ")"
	")";
static const char *s_pattern_auth4_queries =
	"("
	"(@DST@) and udp dst port 53 and " udp_qr_query
	")";
static const char *s_pattern_auth4_responses =
	"("
	"((@SRC@) and udp src port 53 and " udp_qr_response ") or "
	"((@SRC@) and " ipv4_frags ")"
	")";

static const char *s_pattern_res4 =
	"("
	"((@SRC@) and udp dst port 53) or "
	"((@DST@) and udp src port 53) or "
	"((@DST@) and " ipv4_frags ")"
	")";
static const char *s_pattern_res4_queries =
	"((@SRC@) and udp dst port 53 and " udp_qr_query ")";
static const char *s_pattern_res4_responses =
	"("
	"((@DST@) and udp src port 53 and " udp_qr_response ") or "
	"((@DST@) and " ipv4_frags ")"
	")";

#undef ipv4_frags
#undef udp_qr_query
#undef udp_qr_response

static const char *s_pattern_auth6 =
	"((@DST@) or (@SRC@))";

static const char *s_pattern_res6 =
	"((@SRC@) or (@DST@))";

static char *
bpf_replace(const char *s_pattern, const char *bpf_src, const char *bpf_dst) {
	char *rep0, *rep1;
	rep0 = string_replace(s_pattern, "@SRC@", bpf_src);
	rep1 = string_replace(rep0, "@DST@", bpf_dst);
	free(rep0);
	return (rep1);
}

static nmsg_res
dnsqr_pcap_init(void *clos, nmsg_pcap_t pcap) {
	dnsqr_ctx_t *ctx = (dnsqr_ctx_t *) clos;
	const char *auth_addrs = NULL;
	const char *res_addrs = NULL;
	nmsg_res res;

	bool do_auth4 = false;
	bool do_auth6 = false;
	bool do_res4 = false;
	bool do_res6 = false;

	char *bpf = NULL;
	char *bpf_auth = NULL;
	char *bpf_auth4 = NULL;
	char *bpf_auth4_dst = NULL;
	char *bpf_auth4_src = NULL;
	char *bpf_auth6 = NULL;
	char *bpf_auth6_dst = NULL;
	char *bpf_auth6_src = NULL;
	char *bpf_res = NULL;
	char *bpf_res4 = NULL;
	char *bpf_res4_dst = NULL;
	char *bpf_res4_src = NULL;
	char *bpf_res6 = NULL;
	char *bpf_res6_dst = NULL;
	char *bpf_res6_src = NULL;

	auth_addrs = getenv("DNSQR_AUTH_ADDRS");
	if (auth_addrs) {
		bpf_auth4_src = addrs_to_bpf(auth_addrs, "src", AF_INET);
		bpf_auth4_dst = addrs_to_bpf(auth_addrs, "dst", AF_INET);
		bpf_auth6_src = addrs_to_bpf(auth_addrs, "src", AF_INET6);
		bpf_auth6_dst = addrs_to_bpf(auth_addrs, "dst", AF_INET6);

		if (bpf_auth4_src == NULL ||
		    bpf_auth4_dst == NULL ||
		    bpf_auth6_src == NULL ||
		    bpf_auth6_dst == NULL)
		{
			res = nmsg_res_failure;
			goto out;
		}

		do_auth4 = (strlen(bpf_auth4_src) > 0) ? true : false;
		do_auth6 = (strlen(bpf_auth6_src) > 0) ? true : false;

		if (do_auth4) {
			if (ctx->capture_qr == -1) {
				bpf_auth4 = bpf_replace(s_pattern_auth4,
							bpf_auth4_src,
							bpf_auth4_dst);
			} else if (ctx->capture_qr == 0) {
				bpf_auth4 = bpf_replace(s_pattern_auth4_queries,
							bpf_auth4_src,
							bpf_auth4_dst);
			} else if (ctx->capture_qr == 1) {
				bpf_auth4 = bpf_replace(s_pattern_auth4_responses,
							bpf_auth4_src,
							bpf_auth4_dst);
			}
		}
		if (do_auth6)
			bpf_auth6 = bpf_replace(s_pattern_auth6, bpf_auth6_src, bpf_auth6_dst);

		nmsg_asprintf(&bpf_auth, "%s%s%s",
			      (do_auth4) ? bpf_auth4 : "",
			      (do_auth4 && do_auth6) ? " or " : "",
			      (do_auth6) ? bpf_auth6 : ""
		);
		assert(bpf_auth != NULL);
	}

	res_addrs = getenv("DNSQR_RES_ADDRS");
	if (res_addrs) {
		bpf_res4_src = addrs_to_bpf(res_addrs, "src", AF_INET);
		bpf_res4_dst = addrs_to_bpf(res_addrs, "dst", AF_INET);
		bpf_res6_src = addrs_to_bpf(res_addrs, "src", AF_INET6);
		bpf_res6_dst = addrs_to_bpf(res_addrs, "dst", AF_INET6);

		if (bpf_res4_src == NULL ||
		    bpf_res4_dst == NULL ||
		    bpf_res6_src == NULL ||
		    bpf_res6_dst == NULL)
		{
			res = nmsg_res_failure;
			goto out;
		}

		do_res4 = (strlen(bpf_res4_src) > 0) ? true : false;
		do_res6 = (strlen(bpf_res6_src) > 0) ? true : false;

		if (do_res4) {
			if (ctx->capture_qr == -1) {
				bpf_res4 = bpf_replace(s_pattern_res4,
						       bpf_res4_src,
						       bpf_res4_dst);
			} else if (ctx->capture_qr == 0) {
				bpf_res4 = bpf_replace(s_pattern_res4_queries,
						       bpf_res4_src,
						       bpf_res4_dst);
			} else if (ctx->capture_qr == 1) {
				bpf_res4 = bpf_replace(s_pattern_res4_responses,
						       bpf_res4_src,
						       bpf_res4_dst);
			}
		}
		if (do_res6)
			bpf_res6 = bpf_replace(s_pattern_res6, bpf_res6_src, bpf_res6_dst);

		nmsg_asprintf(&bpf_res, "%s%s%s",
			      (do_res4) ? bpf_res4 : "",
			      (do_res4 && do_res6) ? " or " : "",
			      (do_res6) ? bpf_res6 : "");
		assert(bpf_res != NULL);
	}

	if (!auth_addrs && !res_addrs)
		return (nmsg_res_success);

	nmsg_asprintf(&bpf, "%s%s%s",
		     (bpf_auth != NULL) ? bpf_auth : "",
		     ((bpf_auth != NULL) && (bpf_res != NULL)) ? " or " : "",
		     (bpf_res != NULL) ? bpf_res : "");
	assert(bpf != NULL);

	res = nmsg_pcap_input_setfilter_raw(pcap, bpf);

out:
	free(bpf);
	free(bpf_auth);
	free(bpf_auth4);
	free(bpf_auth4_dst);
	free(bpf_auth4_src);
	free(bpf_auth6);
	free(bpf_auth6_dst);
	free(bpf_auth6_src);
	free(bpf_res);
	free(bpf_res4);
	free(bpf_res4_dst);
	free(bpf_res4_src);
	free(bpf_res6);
	free(bpf_res6_dst);
	free(bpf_res6_src);
	return (res);
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
	case IPPROTO_UDP: {
		const char str[] = "proto: UDP (17)\n";
		return (nmsg_strbuf_append_str(sb, str, sizeof(str) - 1));
	}
	case IPPROTO_TCP: {
		const char str[] = "proto: TCP (6)\n";
		return (nmsg_strbuf_append_str(sb, str, sizeof(str) - 1));
	}
	case IPPROTO_ICMP: {
		const char str[] = "proto: ICMP (1)\n";
		return (nmsg_strbuf_append_str(sb, str, sizeof(str) - 1));
	}
	default:
		return (nmsg_strbuf_append(sb, "proto: %hu\n", proto));
	}
}

static nmsg_res
dnsqr_proto_format(nmsg_message_t msg,
		   struct nmsg_msgmod_field *field,
		   void *ptr,
		   struct nmsg_strbuf *sb,
		   const char *endline)
{
	uint16_t proto;

	proto = *((uint16_t *) ptr);

	switch (proto) {
	case IPPROTO_UDP: {
		return (nmsg_strbuf_append_str(sb, "UDP", 3));
	}
	case IPPROTO_TCP: {
		return (nmsg_strbuf_append_str(sb, "TCP", 3));
	}
	case IPPROTO_ICMP: {
		return (nmsg_strbuf_append_str(sb, "ICMP", 4));
	}
	default:
		return (nmsg_strbuf_append(sb, "%hu", proto));
	}
}

static nmsg_res
dnsqr_proto_parse(nmsg_message_t msg,
		  struct nmsg_msgmod_field *field,
		  const char *value,
		  void **ptr,
		  size_t *len,
		  const char *endline)
{
	uint16_t *proto;

	proto = malloc(sizeof(*proto));
	if (proto == NULL)
		return (nmsg_res_memfail);

	if (strcasecmp(value, "UDP") == 0) {
		*proto = IPPROTO_UDP;
	} else if (strcasecmp(value, "TCP") == 0) {
		*proto = IPPROTO_TCP;
	} else if (strcasecmp(value, "ICMP") == 0) {
		*proto = IPPROTO_ICMP;
	} else {
		if (sscanf(value, "%hu", proto) != 1) {
			free(proto);
			return (nmsg_res_parse_error);
		}
	}

	*ptr = proto;
	*len = sizeof(*proto);

	return (nmsg_res_success);
}

static nmsg_res
dnsqr_message_print(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    void *ptr,
		    struct nmsg_strbuf *sb,
		    const char *endline)
{
	ProtobufCBinaryData *bdata;
	nmsg_res res;
	wdns_message_t dns;
	wdns_res status;

	bdata = (ProtobufCBinaryData *) ptr;
	if (bdata == NULL)
		return (nmsg_res_failure);

	status = wdns_parse_message(&dns, bdata->data, bdata->len);
	if (status == wdns_res_success) {
		char *s;

		s = wdns_message_to_str(&dns);
		if (s != NULL) {
			res = nmsg_strbuf_append(sb, "%s: [%zd octets]%s%s---%s",
						 field->name, bdata->len, endline, s, endline);
			free(s);
			wdns_clear_message(&dns);
			return (res);
		}
		wdns_clear_message(&dns);
	}
	nmsg_strbuf_append(sb, "%s: <PARSE ERROR>%s", field->name, endline);
	return (nmsg_res_success);
}

static void
nmsg_rrset_array_to_json(const wdns_rrset_array_t *a, unsigned sec, struct nmsg_strbuf *sb)
{
	char name[WDNS_PRESLEN_NAME];
	char *str;
	const char *cstr;

	nmsg_strbuf_append_str(sb, "[", 1);

	for (unsigned i = 0; i < a->n_rrsets; i++) {
		wdns_rrset_t *rrset = &a->rrsets[i];
		if (i > 0) {
			nmsg_strbuf_append_str(sb, ",", 1);
		}

		nmsg_strbuf_append_str(sb, "{", 1);
		declare_json_value(sb, (sec == WDNS_MSG_SEC_QUESTION) ? "qname": "rrname", true);
		wdns_domain_to_str(rrset->name.data, rrset->name.len, name);
		append_json_value_string(sb, name, 0);

		if (sec != WDNS_MSG_SEC_QUESTION) {
			declare_json_value(sb, "rrttl", false);
			append_json_value_int(sb, rrset->rrttl);
		}

		cstr = wdns_rrclass_to_str(rrset->rrclass);
		declare_json_value(sb, (sec == WDNS_MSG_SEC_QUESTION) ? "qclass": "rrclass", false);
		if (cstr) {
			append_json_value_string(sb, cstr, strlen(cstr));
		} else {
			nmsg_strbuf_append(sb, "\"CLASS%u\"", rrset->rrclass);
		}

		cstr = wdns_rrtype_to_str(rrset->rrtype);
		declare_json_value(sb, (sec == WDNS_MSG_SEC_QUESTION) ? "qtype": "rrtype", false);
		if (cstr) {
			append_json_value_string(sb, cstr, strlen(cstr));
		} else {
			nmsg_strbuf_append(sb, "\"TYPE%u\"", rrset->rrclass);
		}

		if (sec != WDNS_MSG_SEC_QUESTION) {
			declare_json_value(sb, "rdata", false);
			nmsg_strbuf_append_str(sb, "[", 1);
			for (unsigned j = 0; j < rrset->n_rdatas; j++) {
				if (j > 0) {
					nmsg_strbuf_append_str(sb, ",", 1);
				}

				str = wdns_rdata_to_str(rrset->rdatas[j]->data,
							rrset->rdatas[j]->len,
							rrset->rrtype,
							rrset->rrclass);
				if (str != NULL) {
					append_json_value_string(sb, str, strlen(str));
					free(str);
				} else {
					append_json_value_null(sb);
				}
			}
			nmsg_strbuf_append_str(sb, "]", 1);
		}
		nmsg_strbuf_append_str(sb, "}", 1);

	}
	nmsg_strbuf_append_str(sb, "]", 1);
}

static bool
dnsqr_append_flag(struct nmsg_strbuf *sb, bool value, bool first, const char *flag, size_t flaglen)
{
	if (value) {
		if (!first) {
			nmsg_strbuf_append_str(sb, ",", 1);
		}
		append_json_value_string(sb, flag, flaglen);
		first = false;
	}

	return first;
}

static nmsg_res
dnsqr_message_format(nmsg_message_t msg, struct nmsg_msgmod_field *field,
		     void *ptr, struct nmsg_strbuf *sb, const char *endline)
{
	ProtobufCBinaryData *bdata;
	wdns_message_t dns;
	wdns_res status;

	bdata = (ProtobufCBinaryData *) ptr;
	if (bdata == NULL)
		return (nmsg_res_failure);

	status = wdns_parse_message(&dns, bdata->data, bdata->len);
	if (status == wdns_res_success) {
		const char *rcode, *opcode;
		char *str = NULL;
		bool first = true;

		nmsg_strbuf_append_str(sb, "{", 1);

		declare_json_value(sb, "header", true);
		nmsg_strbuf_append_str(sb, "{", 1);

		declare_json_value(sb, "opcode", true);
		opcode = wdns_opcode_to_str(WDNS_FLAGS_OPCODE(dns));
		if (opcode != NULL) {
			append_json_value_string_noescape(sb, opcode, strlen(opcode));
		} else {
			append_json_value_int(sb, WDNS_FLAGS_OPCODE(dns));
		}

		declare_json_value(sb, "rcode", false);
		rcode = wdns_rcode_to_str(WDNS_FLAGS_RCODE(dns));
		if (rcode != NULL) {
			append_json_value_string_noescape(sb, rcode, strlen(rcode));
		} else {
			append_json_value_int(sb, WDNS_FLAGS_RCODE(dns));
		}

		declare_json_value(sb, "id", false);
		append_json_value_int(sb, dns.id);

		declare_json_value(sb, "flags", false);
		nmsg_strbuf_append_str(sb, "[", 1);

		first = dnsqr_append_flag(sb, WDNS_FLAGS_QR(dns), first, "qr", 2);
		first = dnsqr_append_flag(sb, WDNS_FLAGS_AA(dns), first, "aa", 2);
		first = dnsqr_append_flag(sb, WDNS_FLAGS_TC(dns), first, "tc", 2);
		first = dnsqr_append_flag(sb, WDNS_FLAGS_RD(dns), first, "rd", 2);
		first = dnsqr_append_flag(sb, WDNS_FLAGS_RA(dns), first, "ra", 2);
		first = dnsqr_append_flag(sb, WDNS_FLAGS_AD(dns), first, "ad", 2);
		first = dnsqr_append_flag(sb, WDNS_FLAGS_CD(dns), first, "cd", 2);

		nmsg_strbuf_append_str(sb, "]", 1);        /* end header flags */

		if (dns.edns.present) {
			declare_json_value(sb, "opt", false);
			nmsg_strbuf_append_str(sb, "{", 1);

			declare_json_value(sb, "edns", true);
			nmsg_strbuf_append_str(sb, "{", 1);

			declare_json_value(sb, "version", true);
			append_json_value_int(sb, dns.edns.version);

			declare_json_value(sb, "flags", false);

			nmsg_strbuf_append_str(sb, "[", 1);
			(void) dnsqr_append_flag(sb, (dns.edns.flags & 0x8000) != 0, true, "do", 2);
			nmsg_strbuf_append_str(sb, "]", 1);        /* end edns flags */

			declare_json_value(sb, "udp", false);
			append_json_value_int(sb, dns.edns.size);

			if (dns.edns.options != NULL) {
				declare_json_value(sb, "options", false);
				nmsg_strbuf_append_str(sb, "[", 1);
				str = wdns_rdata_to_str(dns.edns.options->data,
							dns.edns.options->len, WDNS_TYPE_OPT, 0);
				if (str != NULL) {
					char *opt, *saveptr;
					bool put_comma = false;
					opt = strtok_r(str, "\n", &saveptr);
					while (opt != NULL) {
						if (put_comma) {
							nmsg_strbuf_append_str(sb, ",", 1);
						} else {
							put_comma = true;
						}
						append_json_value_string(sb, opt, strlen(opt));
						opt = strtok_r(NULL, "\n", &saveptr);
					}
					free(str);
				} else {
					append_json_value_null(sb);
				}
				nmsg_strbuf_append_str(sb, "]", 1);
			}
			nmsg_strbuf_append_str(sb, "}}", 2);        /* edns } opt } */
		}
		nmsg_strbuf_append_str(sb, "}", 1);	/* end header */

		declare_json_value(sb, "question", false);
		nmsg_rrset_array_to_json(&dns.sections[WDNS_MSG_SEC_QUESTION], WDNS_MSG_SEC_QUESTION, sb);

		declare_json_value(sb, "answer", false);
		nmsg_rrset_array_to_json(&dns.sections[WDNS_MSG_SEC_ANSWER], WDNS_MSG_SEC_ANSWER, sb);

		declare_json_value(sb, "authority", false);
		nmsg_rrset_array_to_json(&dns.sections[WDNS_MSG_SEC_AUTHORITY], WDNS_MSG_SEC_AUTHORITY, sb);

		declare_json_value(sb, "additional", false);
		nmsg_rrset_array_to_json(&dns.sections[WDNS_MSG_SEC_ADDITIONAL], WDNS_MSG_SEC_ADDITIONAL, sb);

		nmsg_strbuf_append_str(sb, "}", 1);
		wdns_clear_message(&dns);
	} else {
		append_json_value_null(sb);
	}

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
dnsqr_rcode_format(nmsg_message_t msg,
		   struct nmsg_msgmod_field *field,
		   void *ptr,
		   struct nmsg_strbuf *sb,
		   const char *endline)
{
	const char *s;
	uint16_t *rcode = ptr;

	s = wdns_rcode_to_str(*rcode);
	if (s != NULL)
		return (nmsg_strbuf_append_str(sb, s, strlen(s)));
	else
		return (nmsg_strbuf_append(sb, "%hu", *rcode));
}

static nmsg_res
dnsqr_rcode_parse(nmsg_message_t msg,
		  struct nmsg_msgmod_field *field,
		  const char *value,
		  void **ptr,
		  size_t *len,
		  const char *endline)
{
	uint16_t *rcode;
	wdns_res res;

	rcode = malloc(sizeof(*rcode));
	if (rcode == NULL) {
		return (nmsg_res_memfail);
	}

	res = wdns_str_to_rcode(value, rcode);
	if (res != wdns_res_success) {
		char *endp;
		errno = 0;
		unsigned long lvalue = strtoul(value, &endp, 0);
		if (errno != 0 || *endp != '\0' || lvalue > 15) {
			free(rcode);
			return (nmsg_res_parse_error);
		}
		*rcode = (uint16_t) lvalue;
	}

	*ptr = rcode;
	*len = sizeof(*rcode);

	return (nmsg_res_success);
}

static nmsg_res
dnsqr_get_udp_checksum(nmsg_message_t msg,
		       struct nmsg_msgmod_field *field,
		       unsigned val_idx,
		       void **data,
		       size_t *len,
		       void *msg_clos)
{
	Nmsg__Base__DnsQR *dnsqr = (Nmsg__Base__DnsQR *) nmsg_message_get_payload(msg);

	if (dnsqr == NULL || val_idx != 0 || dnsqr->n_response_packet <= 0)
		return (nmsg_res_failure);

	if (!dnsqr->has_udp_checksum)
		dnsqr->udp_checksum = dnsqr_checksum_verify(dnsqr);
	*data = (void *) &dnsqr->udp_checksum;
	if (len)
		*len = sizeof(dnsqr->udp_checksum);

	return (nmsg_res_success);
}

static nmsg_res
dnsqr_get_delay(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		unsigned val_idx,
		void **data,
		size_t *len,
		void *msg_clos)
{
	Nmsg__Base__DnsQR *dnsqr = (Nmsg__Base__DnsQR *) nmsg_message_get_payload(msg);
	double delay;
	double *pdelay;
	struct timespec ts_delay;

	if (dnsqr == NULL || val_idx != 0 ||
	    dnsqr->type != NMSG__BASE__DNS_QR__DNS_QRTYPE__UDP_QUERY_RESPONSE)
		return (nmsg_res_failure);

	if ((dnsqr->n_query_time_sec != dnsqr->n_query_time_nsec) ||
	    dnsqr->n_query_time_sec != 1)
		return (nmsg_res_failure);

	if ((dnsqr->n_response_time_sec != dnsqr->n_response_time_nsec) ||
	    dnsqr->n_response_time_sec < 1)
		return (nmsg_res_failure);

	if (dnsqr->n_response_time_sec == 1) {
		ts_delay.tv_sec = dnsqr->response_time_sec[0] - dnsqr->query_time_sec[0];
		ts_delay.tv_nsec = dnsqr->response_time_nsec[0] - dnsqr->query_time_nsec[0];
		if (ts_delay.tv_nsec < 0) {
			ts_delay.tv_sec -= 1;
			ts_delay.tv_nsec += 1000000000;
		}
		delay = ts_delay.tv_sec + ts_delay.tv_nsec / 1E9;
	} else {
		double max_delay = 0.0;

		for (unsigned i = 0; i < dnsqr->n_response_time_sec; i++) {
			ts_delay.tv_sec = dnsqr->response_time_sec[i] - dnsqr->query_time_sec[0];
			ts_delay.tv_nsec = dnsqr->response_time_nsec[i] - dnsqr->query_time_nsec[0];
			if (ts_delay.tv_nsec < 0) {
				ts_delay.tv_sec -= 1;
				ts_delay.tv_nsec += 1000000000;
			}
			delay = ts_delay.tv_sec + ts_delay.tv_nsec / 1E9;

			if (delay > max_delay)
				max_delay = delay;
		}
		delay = max_delay;
	}

	pdelay = my_malloc(sizeof(double));
	*pdelay = delay;

	*data = (void *) pdelay;
	if (len)
		*len = sizeof(double);

	return (nmsg_message_add_allocation(msg, pdelay));
}

static nmsg_res
dnsqr_get_query(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		unsigned val_idx,
		void **data,
		size_t *len,
		void *msg_clos)
{
	Nmsg__Base__DnsQR *dnsqr = (Nmsg__Base__DnsQR *) nmsg_message_get_payload(msg);
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
	Nmsg__Base__DnsQR *dnsqr = (Nmsg__Base__DnsQR *) nmsg_message_get_payload(msg);
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

		list_head = my_calloc(1, sizeof(*list_head));
		entry = my_calloc(1, sizeof(*entry));

		entry->frags = list_head;
		entry->holes = 1;

		for (n = 0; n < dnsqr->n_response_packet; n++) {
			ts.tv_sec = dnsqr->response_time_sec[n];
			ts.tv_nsec = dnsqr->response_time_nsec[n];

			frag = reasm_parse_packet(dnsqr->response_packet[n].data,
						  dnsqr->response_packet[n].len,
						  &ts, &proto, &id, &hash, &last_frag);
			entry->protocol = proto;
			if (frag == NULL ||
			    reasm_add_fragment(entry, frag, last_frag) == false)
			{
				reasm_free_entry(entry);
				return (nmsg_res_memfail);
			}
		}
		if (reasm_is_complete(entry)) {
			pkt_len = NMSG_IPSZ_MAX;
			pkt = my_malloc(NMSG_IPSZ_MAX);
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
dnsqr_eq6(Nmsg__Base__DnsQR *d1, Nmsg__Base__DnsQR *d2) {
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
dnsqr_eq9(Nmsg__Base__DnsQR *d1, Nmsg__Base__DnsQR *d2) {
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
dnsqr_eq(Nmsg__Base__DnsQR *d1, Nmsg__Base__DnsQR *d2, uint16_t rcode) {
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
dnsqr_hash(Nmsg__Base__DnsQR *dnsqr) {
	dnsqr_key_t key;
	dnsqr_key6_t key6;
	size_t len = 0;
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

	hash = my_hashlittle(k, len, 0);
	return (hash);
}

static void
dnsqr_insert_query(dnsqr_ctx_t *ctx, Nmsg__Base__DnsQR *dnsqr) {
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
			ctx->count += 1;
			he->dnsqr = dnsqr;

			le = my_calloc(1, sizeof(*le));
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

static Nmsg__Base__DnsQR *
dnsqr_trim(dnsqr_ctx_t *ctx) {
	Nmsg__Base__DnsQR *dnsqr = NULL;
	list_entry_t *le;
	hash_entry_t *he;
	struct timespec timeout;

	/* lock hash table */
	pthread_mutex_lock(&ctx->lock);

	le = ISC_LIST_HEAD(ctx->list);

	if (le != NULL) {
		assert(le->he != NULL);
		he = le->he;
		assert(he->dnsqr != NULL);
		assert(he->dnsqr->n_query_time_sec > 0);
		assert(he->dnsqr->n_query_time_nsec > 0);
		if (ctx->count > ctx->max_values ||
		    ctx->stop == true ||
		    ctx->now.tv_sec - he->dnsqr->query_time_sec[0] > ctx->query_timeout)
		{
			dnsqr = he->dnsqr;
			dnsqr_remove(ctx, he);

			timeout.tv_sec = ctx->now.tv_sec - dnsqr->query_time_sec[0];
			timeout.tv_nsec = ctx->now.tv_nsec - dnsqr->query_time_nsec[0];
			if (timeout.tv_nsec < 0) {
				timeout.tv_sec -= 1;
				timeout.tv_nsec += 1000000000;
			}
			dnsqr->timeout = timeout.tv_sec + (((double) timeout.tv_nsec) / 1E9);
			dnsqr->has_timeout = true;

#ifdef DEBUG
			ctx->count_unanswered_query += 1;
#endif
		}
	}

	/* unlock hash table */
	pthread_mutex_unlock(&ctx->lock);

	return (dnsqr);
}

static Nmsg__Base__DnsQR *
dnsqr_retrieve(dnsqr_ctx_t *ctx, Nmsg__Base__DnsQR *dnsqr, uint16_t rcode) {
	Nmsg__Base__DnsQR *query = NULL;
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
dnsqr_to_message(dnsqr_ctx_t *ctx, Nmsg__Base__DnsQR *dnsqr) {
	ProtobufCBufferSimple sbuf = {{0}};
	nmsg_message_t m;
	size_t buf_sz;
	struct timespec ts;

	if (dnsqr->n_response_packet > 0) {
		dnsqr->udp_checksum = dnsqr_checksum_verify(dnsqr);
		dnsqr->has_udp_checksum = true;
	}

	if (ctx->zero_resolver_address)
		dnsqr_zero_resolver_address(dnsqr);

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.data = my_malloc(1024);
	sbuf.must_free_data = 1;
	sbuf.alloced = 1024;

	buf_sz = protobuf_c_message_pack_to_buffer((ProtobufCMessage *) dnsqr,
						   (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL)
		return (NULL);

	m = nmsg_message_from_raw_payload(NMSG_VENDOR_BASE_ID,
					  NMSG_VENDOR_BASE_DNSQR_ID,
					  sbuf.data, buf_sz, NULL);
	assert(m != NULL);

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
do_packet_dns(Nmsg__Base__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const uint8_t *p;
	size_t len;
	uint16_t qdcount;
	uint16_t qtype;
	uint16_t qclass;

	p = dg->payload;
	len = dg->len_payload;

	if (len < 12)
		return (nmsg_res_again);

	load_net16(p, &dnsqr->id);
	load_net16(p + 2, flags);
	load_net16(p + 4, &qdcount);

	p += 12;
	len -= 12;

	if (qdcount == 1 && len > 0) {
		dnsqr->qname.len = wdns_skip_name(&p, p + len);
		dnsqr->qname.data = my_malloc(dnsqr->qname.len);
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
do_packet_udp(Nmsg__Base__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const struct nmsg_udphdr *udp;
	nmsg_res res;
	uint16_t src_port;
	uint16_t dst_port;

	udp = (const struct nmsg_udphdr *) dg->transport;
	if (udp == NULL)
		return (nmsg_res_again);
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
do_packet_tcp(Nmsg__Base__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const struct nmsg_tcphdr *tcp;
	uint16_t src_port;
	uint16_t dst_port;

	tcp = (const struct nmsg_tcphdr *) dg->transport;
	if (tcp  == NULL)
		return (nmsg_res_again);
	src_port = ntohs(tcp->th_sport);
	dst_port = ntohs(tcp->th_dport);

	if (!(src_port == 53 || dst_port == 53))
		return (nmsg_res_again);

	dnsqr->tcp.data = my_malloc(dg->len_network);
	memcpy(dnsqr->tcp.data, dg->network, dg->len_network);
	dnsqr->tcp.len = dg->len_network;
	dnsqr->has_tcp = true;

	dnsqr->type = NMSG__BASE__DNS_QR__DNS_QRTYPE__TCP;

	return (nmsg_res_success);
}

static nmsg_res
do_packet_icmp(Nmsg__Base__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	struct nmsg_ipdg icmp_dg;
	nmsg_res res;
	uint16_t src_port;
	uint16_t dst_port;

	res = nmsg_ipdg_parse_pcap_raw(&icmp_dg, DLT_RAW, dg->payload, dg->len_payload);
	if (res != nmsg_res_success)
		return (res);
	if (icmp_dg.transport == NULL)
		return (nmsg_res_again);
	if (icmp_dg.proto_transport == IPPROTO_UDP) {
		const struct nmsg_udphdr *udp;

		udp = (const struct nmsg_udphdr *) icmp_dg.transport;
		src_port = ntohs(udp->uh_sport);
		dst_port = ntohs(udp->uh_dport);

		if (!(src_port == 53 || src_port == 5353 || dst_port == 53 || dst_port == 5353))
			return (nmsg_res_again);
	} else if (icmp_dg.proto_transport == IPPROTO_TCP) {
		const struct nmsg_tcphdr *tcp;

		tcp = (const struct nmsg_tcphdr *) icmp_dg.transport;
		src_port = ntohs(tcp->th_sport);
		dst_port = ntohs(tcp->th_dport);

		if (!(src_port == 53 || dst_port == 53))
			return (nmsg_res_again);
	} else {
		return (nmsg_res_again);
	}

	dnsqr->icmp.data = my_malloc(dg->len_network);
	memcpy(dnsqr->icmp.data, dg->network, dg->len_network);
	dnsqr->icmp.len = dg->len_network;
	dnsqr->has_icmp = true;

	dnsqr->type = NMSG__BASE__DNS_QR__DNS_QRTYPE__ICMP;

	return (nmsg_res_success);
}

static nmsg_res
do_packet_v4(Nmsg__Base__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
	const struct nmsg_iphdr *ip;
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
	dnsqr->query_ip.len = 4;
	dnsqr->query_ip.data = my_malloc(4);

	/* allocate response_ip */
	dnsqr->response_ip.len = 4;
	dnsqr->response_ip.data = my_malloc(4);

	ip = (const struct nmsg_iphdr *) dg->network;

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
do_packet_v6(Nmsg__Base__DnsQR *dnsqr, struct nmsg_ipdg *dg, uint16_t *flags) {
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
	dnsqr->query_ip.data = my_malloc(16);

	/* allocate response_ip */
	dnsqr->response_ip.len = 16;
	dnsqr->response_ip.data = my_malloc(16);

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

static bool
get_query_flags(Nmsg__Base__DnsQR *dnsqr, uint16_t *flags) {
	nmsg_res res;
	struct nmsg_ipdg dg;

	if (dnsqr->query_ip.data != NULL && dnsqr->n_query_packet > 0) {
		if (dnsqr->query_ip.len == 4) {
			res = nmsg_ipdg_parse(&dg, ETHERTYPE_IP,
					      dnsqr->query_packet[0].len,
					      dnsqr->query_packet[0].data);
			if (res != nmsg_res_success)
				return (false);
		} else if (dnsqr->query_ip.len == 16) {
			res = nmsg_ipdg_parse(&dg, ETHERTYPE_IPV6,
					      dnsqr->query_packet[0].len,
					      dnsqr->query_packet[0].data);
			if (res != nmsg_res_success)
				return (false);
		} else {
			return (false);
		}
	} else {
		return (false);
	}

	if (dg.len_payload >= 12) {
		memcpy(flags, dg.payload + 2, sizeof(*flags));
		*flags = htons(*flags);
		return (true);
	}

	return (false);
}

static void
dnsqr_merge(Nmsg__Base__DnsQR *d1, Nmsg__Base__DnsQR *d2) {
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

	nmsg__base__dns_qr__free_unpacked(d1, NULL);
}

#define extend_field_array(x, n) do { \
	(x) = realloc((x), (n) * sizeof(*(x))); \
	assert((x) != NULL); \
} while (0)

static nmsg_res
dnsqr_append_query_packet(Nmsg__Base__DnsQR *dnsqr,
			  const uint8_t *pkt, size_t pkt_len,
			  const struct timespec *ts)
{
	size_t n, idx;
	uint8_t *pkt_copy;

	n = idx = dnsqr->n_query_packet;
	n += 1;

	extend_field_array(dnsqr->query_packet, n);
	extend_field_array(dnsqr->query_time_sec, n);
	extend_field_array(dnsqr->query_time_nsec, n);

	pkt_copy = my_malloc(pkt_len);
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
dnsqr_append_response_packet(Nmsg__Base__DnsQR *dnsqr,
			     const uint8_t *pkt, size_t pkt_len,
			     const struct timespec *ts)
{
	size_t n, idx;
	uint8_t *pkt_copy;

	n = idx = dnsqr->n_response_packet;
	n += 1;

	extend_field_array(dnsqr->response_packet, n);
	extend_field_array(dnsqr->response_time_sec, n);
	extend_field_array(dnsqr->response_time_nsec, n);

	pkt_copy = my_malloc(pkt_len);
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
		  Nmsg__Base__DnsQR *dnsqr,
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

static bool
do_filter_query_rd(dnsqr_ctx_t *ctx, Nmsg__Base__DnsQR *dnsqr) {
	if (ctx->capture_rd == 0 || ctx->capture_rd == 1) {
		uint16_t qflags;
		if (get_query_flags(dnsqr, &qflags))
			if (DNS_FLAG_RD(qflags) != ctx->capture_rd)
				return (true);
	}
	return (false);
}

static bool
do_filter_rd(dnsqr_ctx_t *ctx, uint16_t flags) {
	if (ctx->capture_rd == 0 || ctx->capture_rd == 1) {
		if (DNS_FLAG_RD(flags) != ctx->capture_rd)
			return (true);
	}
	return (false);
}

static bool
do_filter_query_name(dnsqr_ctx_t *ctx, Nmsg__Base__DnsQR *dnsqr) {
	wdns_name_t name;
	wdns_res res;

	if (dnsqr->has_qname == false)
		return (false);

	if (ctx->filter_qnames_include != NULL) {
		name.len = dnsqr->qname.len;
		name.data = alloca(name.len);
		assert(name.data != NULL);
		memcpy(name.data, dnsqr->qname.data, name.len);
		wdns_downcase_name(&name);

		for (;;) {
			if (dnsqr_filter_lookup(ctx->filter_qnames_include,
						ctx->filter_qnames_include_slots,
						&name))
			{
				return (false);
			}
			if (name.len == 1)
				break;
			res = wdns_left_chop(&name, &name);
			if (res != wdns_res_success)
				break;
		}
	}

	if (ctx->filter_qnames_exclude != NULL) {
		name.len = dnsqr->qname.len;
		name.data = alloca(name.len);
		assert(name.data != NULL);
		memcpy(name.data, dnsqr->qname.data, name.len);
		wdns_downcase_name(&name);

		for (;;) {
			if (dnsqr_filter_lookup(ctx->filter_qnames_exclude,
						ctx->filter_qnames_exclude_slots,
						&name))
			{
				return (true);
			}
			if (name.len == 1)
				break;
			res = wdns_left_chop(&name, &name);
			if (res != wdns_res_success)
				break;
		}
	}

	return (false);
}

static bool
do_filter(dnsqr_ctx_t *ctx, Nmsg__Base__DnsQR *dnsqr) {
	return (do_filter_query_rd(ctx, dnsqr) ||
		do_filter_query_name(ctx, dnsqr));
}

static nmsg_res
do_packet(dnsqr_ctx_t *ctx, nmsg_pcap_t pcap, nmsg_message_t *m,
	  const uint8_t *pkt, const struct pcap_pkthdr *pkt_hdr,
	  const struct timespec *ts)
{
	Nmsg__Base__DnsQR *dnsqr = NULL;
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
			new_pkt = my_malloc(NMSG_IPSZ_MAX);
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

	if (dg.transport == NULL)
		return (nmsg_res_again);

	dnsqr = my_calloc(1, sizeof(*dnsqr));
	nmsg__base__dns_qr__init(dnsqr);

	dnsqr->proto = dg.proto_transport;

	switch (dg.proto_network) {
	case PF_INET:
		res = do_packet_v4(dnsqr, &dg, &flags);
		break;
	case PF_INET6:
		/* refilter since nmsg_pcap_setfilter() results in a filter that
		 * accepts all IPv6 packets */
		if (nmsg_pcap_filter(pcap, dg.network, dg.len_network) == false) {
			res = nmsg_res_again;
			goto out;
		}
		res = do_packet_v6(dnsqr, &dg, &flags);
		break;
	default:
		res = nmsg_res_again;
		break;
	}

	if (res != nmsg_res_success)
		goto out;

	if (dg.proto_transport == IPPROTO_UDP && ctx->capture_qr != -1) {
		/* udp query-response state reconstruction disabled */

		if (ctx->capture_qr == 0 && DNS_FLAG_QR(flags) == false) {
			/* udp query */
			dnsqr->type = NMSG__BASE__DNS_QR__DNS_QRTYPE__UDP_QUERY_ONLY;

			res = dnsqr_append_query_packet(dnsqr, dg.network, dg.len_network, ts);
			if (res != nmsg_res_success)
				goto out;

			*m = dnsqr_to_message(ctx, dnsqr);
			res = nmsg_res_success;
		} else if (ctx->capture_qr == 1 && DNS_FLAG_QR(flags) == true) {
			/* udp response */
			dnsqr->type = NMSG__BASE__DNS_QR__DNS_QRTYPE__UDP_RESPONSE_ONLY;
			dnsqr->rcode = DNS_FLAG_RCODE(flags);
			dnsqr->has_rcode = true;

			if (is_frag)
				res = dnsqr_append_frag(dnsqr_append_response_packet,
							dnsqr,
							reasm_entry);
			else
				res = dnsqr_append_response_packet(dnsqr,
								   dg.network,
								   dg.len_network,
								   ts);
			if (res != nmsg_res_success)
				goto out;

			*m = dnsqr_to_message(ctx, dnsqr);
			res = nmsg_res_success;
		} else {
			res = nmsg_res_again;
		}
	} else if (dg.proto_transport == IPPROTO_UDP && DNS_FLAG_QR(flags) == false) {
		/* message is a query */
		dnsqr->type = NMSG__BASE__DNS_QR__DNS_QRTYPE__UDP_UNANSWERED_QUERY;
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
		Nmsg__Base__DnsQR *query;

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

			dnsqr->type = NMSG__BASE__DNS_QR__DNS_QRTYPE__UDP_UNSOLICITED_RESPONSE;

			if (do_filter_rd(ctx, flags) || do_filter_query_name(ctx, dnsqr)) {
				res = nmsg_res_again;
				goto out;
			}

			*m = dnsqr_to_message(ctx, dnsqr);
			res = nmsg_res_success;
#ifdef DEBUG
			pthread_mutex_lock(&ctx->lock);
			ctx->count_unsolicited_response += 1;
			pthread_mutex_unlock(&ctx->lock);
#endif
		} else {
			/* corresponding query, merge query and response */

			dnsqr->type = NMSG__BASE__DNS_QR__DNS_QRTYPE__UDP_QUERY_RESPONSE;
			dnsqr_merge(query, dnsqr);

			if (do_filter(ctx, dnsqr)) {
				res = nmsg_res_again;
				goto out;
			}

			*m = dnsqr_to_message(ctx, dnsqr);
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
		*m = dnsqr_to_message(ctx, dnsqr);
		nmsg_message_set_time(*m, ts);
	}

out:
	if (dnsqr != NULL)
		nmsg__base__dns_qr__free_unpacked(dnsqr, NULL);
	if (new_pkt != NULL)
		free(new_pkt);
	if (reasm_entry != NULL)
		reasm_free_entry(reasm_entry);
	return (res);
}

static nmsg_res
dnsqr_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m) {
	Nmsg__Base__DnsQR *dnsqr;
	dnsqr_ctx_t *ctx = (dnsqr_ctx_t *) clos;
	nmsg_res res;
	struct timespec ts;
	struct pcap_pkthdr *pkt_hdr;
	const uint8_t *pkt_data;

	dnsqr = dnsqr_trim(ctx);
	if (dnsqr != NULL) {
		if (do_filter(ctx, dnsqr)) {
			nmsg__base__dns_qr__free_unpacked(dnsqr, NULL);
		} else {
			*m = dnsqr_to_message(ctx, dnsqr);
			nmsg__base__dns_qr__free_unpacked(dnsqr, NULL);
			return (nmsg_res_success);
		}
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
