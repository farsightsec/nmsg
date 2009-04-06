/*
 * ipreasm -- Routines for reassembly of fragmented IPv4 and IPv6 packets.
 *
 * Copyright (c) 2007  Jan Andres <jandres@gmx.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "nmsg_port.h"
#include "nmsg_port_net.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include "ipreasm.h"

#define REASM_IP_HASH_SIZE 1021U


enum entry_state {
	STATE_ACTIVE,
	STATE_INVALID
};


enum reasm_proto {
	PROTO_IPV4,
	PROTO_IPV6
};


/*
 * This tuple uniquely identifies all fragments belonging to
 * the same IPv4 packet.
 */
struct reasm_id_ipv4 {
	uint8_t ip_src[4], ip_dst[4];
	uint16_t ip_id;
	uint8_t ip_proto;
};


/*
 * Same for IPv6.
 */
struct reasm_id_ipv6 {
	uint8_t ip_src[16], ip_dst[16];
	uint32_t ip_id;
};


union reasm_id {
	struct reasm_id_ipv4 ipv4;
	struct reasm_id_ipv6 ipv6;
};


struct reasm_frag_entry {
	unsigned len;  /* payload length of this fragment */
	unsigned offset; /* offset of this fragment into the payload of the reassembled packet */
	unsigned data_offset; /* offset to the data pointer where payload starts */
	unsigned char *data; /* payload starts at data + data_offset */
	struct reasm_frag_entry *next;
};


/*
 * Reception of a complete packet is detected by counting the number
 * of "holes" that remain between the cached fragments. A hole is
 * assumed to exist at the upper end of the packet until the final
 * fragment has been received. When the number of holes drops to 0,
 * all fragments have been received and the packet can be reassembled.
 */
struct reasm_ip_entry {
	union reasm_id id;
	unsigned len, holes, frag_count, hash;
	reasm_time_t timeout;
	enum entry_state state;
	enum reasm_proto protocol;
	struct reasm_frag_entry *frags;
	struct reasm_ip_entry *prev, *next;
	struct reasm_ip_entry *time_prev, *time_next;
};


/*
 * This struct contains some metadata, the main hash table, and a pointer
 * to the first entry that will time out. A linked list is kept in the
 * order in which packets will time out. Using a linked list for this
 * purpose requires that packets are input in chronological order, and
 * that a constant timeout value is used, which doesn't change even when
 * the entry's state transitions from active to invalid.
 */
struct reasm_ip {
	struct reasm_ip_entry *table[REASM_IP_HASH_SIZE];
	struct reasm_ip_entry *time_first, *time_last;
	unsigned waiting, max_waiting, timed_out, dropped_frags;
	reasm_time_t timeout;
};


/*
 * Hash functions.
 */
static unsigned reasm_ipv4_hash (const struct reasm_id_ipv4 *id);
static unsigned reasm_ipv6_hash (const struct reasm_id_ipv6 *id);

/*
 * Insert a new fragment to the correct position in the list of fragments.
 * Check for fragment overlap and other error conditions. Update the
 * "hole count".
 */
static bool add_fragment (struct reasm_ip_entry *entry, struct reasm_frag_entry *frag, bool last_frag);

/*
 * Is the entry complete, ready for reassembly?
 */
static bool is_complete (struct reasm_ip_entry *entry);

/*
 * Create the reassembled packet.
 */
static void assemble (struct reasm_ip_entry *entry, unsigned char *out_packet, unsigned *output_len);

/*
 * Drop and free entries.
 */
static void drop_entry (struct reasm_ip *reasm, struct reasm_ip_entry *entry);
static void free_entry (struct reasm_ip_entry *entry);

/*
 * Dispose of any entries which have expired before "now".
 */
static void process_timeouts (struct reasm_ip *reasm, reasm_time_t now);

/*
 * Create fragment structure from IPv6 packet. Returns NULL if the input
 * is not a fragment.
 * This function is called by parse_packet(), don't call it directly.
 */
static struct reasm_frag_entry *frag_from_ipv6 (const unsigned char *packet, unsigned frag_hdr_offset, uint32_t *ip_id, bool *last_frag);

/*
 * Compare packet identification tuples for specified protocol.
 */
static bool reasm_id_equal (enum reasm_proto proto, const union reasm_id *left, const union reasm_id *right);

/*
 * Create fragment structure from an IPv4 or IPv6 packet. Returns NULL
 * if the input is not a fragment.
 */
static struct reasm_frag_entry *parse_packet (const unsigned char *packet, unsigned len, unsigned frag_hdr_offset, enum reasm_proto *protocol, union reasm_id *id, unsigned *hash, bool *last_frag);


static unsigned
reasm_ipv4_hash (const struct reasm_id_ipv4 *id)
{
	unsigned hash = 0;
	int i;

	for (i = 0; i < 4; i++) {
		hash = 37U * hash + id->ip_src[i];
		hash = 37U * hash + id->ip_dst[i];
	}

	hash = 59U * hash + id->ip_id;

	hash = 47U * hash + id->ip_proto;

	return hash;
}


static unsigned
reasm_ipv6_hash (const struct reasm_id_ipv6 *id)
{
	unsigned hash = 0;
	int i;

	for (i = 0; i < 16; i++) {
		hash = 37U * hash + id->ip_src[i];
		hash = 37U * hash + id->ip_dst[i];
	}

	hash = 59U * hash + id->ip_id;

	return hash;
}


bool
reasm_ip_next (struct reasm_ip *reasm, const unsigned char *packet, unsigned len, unsigned frag_hdr_offset, reasm_time_t timestamp, unsigned char *out_packet, unsigned *output_len)
{
	enum reasm_proto proto;
	union reasm_id id;
	unsigned hash = 0;
	bool last_frag = 0;
	struct reasm_frag_entry *frag;
	struct reasm_ip_entry *entry;

	process_timeouts (reasm, timestamp);

	frag = parse_packet (packet, len, frag_hdr_offset, &proto, &id, &hash, &last_frag);
	if (frag == NULL) {
		*output_len = 0;
		return false; /* some packet that we don't recognize as a fragment */
	}

	hash %= REASM_IP_HASH_SIZE;
	entry = reasm->table[hash];
	while (entry != NULL && (proto != entry->protocol || !reasm_id_equal (proto, &id, &entry->id)))
		entry = entry->next;

	if (entry == NULL) {
		struct reasm_frag_entry *list_head;

		entry = malloc (sizeof (*entry));
		if (entry == NULL) {
			free (frag);
			abort ();
		}

		list_head = malloc (sizeof (*list_head));
		if (list_head == NULL) {
			free (frag);
			free (entry);
			abort ();
		}

		memset(entry, 0, sizeof *entry);
		entry->id = id;
		entry->len = 0;
		entry->holes = 1;
		entry->frags = list_head;
		entry->hash = hash;
		entry->protocol = proto;
		entry->timeout = timestamp + reasm->timeout;
		entry->state = STATE_ACTIVE;
		entry->prev = NULL;
		entry->next = reasm->table[hash];
		entry->time_prev = reasm->time_last;
		entry->time_next = NULL;

		memset(list_head, 0, sizeof *list_head);
		list_head->len = 0;
		list_head->offset = 0;
		list_head->data_offset = 0;
		list_head->data = NULL;

		if (entry->next != NULL)
			entry->next->prev = entry;
		reasm->table[hash] = entry;

		if (reasm->time_last != NULL)
			reasm->time_last->time_next = entry;
		else
			reasm->time_first = entry;
		reasm->time_last = entry;

		reasm->waiting++;
		if (reasm->waiting > reasm->max_waiting)
			reasm->max_waiting = reasm->waiting;
	}

	if (entry->state != STATE_ACTIVE) {
		reasm->dropped_frags++;
		*output_len = 0;
        free(frag->data);
        free(frag);
		return true;
	}

	if (!add_fragment (entry, frag, last_frag)) {
		entry->state = STATE_INVALID;
		reasm->dropped_frags += entry->frag_count + 1;
		*output_len = 0;
        free(frag->data);
        free(frag);
		return true;
	}

	if (!is_complete (entry)) {
		*output_len = 0;
		return true;
	}

	assemble (entry, out_packet, output_len);
	drop_entry (reasm, entry);
	return true;
}


static bool
add_fragment (struct reasm_ip_entry *entry, struct reasm_frag_entry *frag, bool last_frag)
{
	bool fit_left, fit_right;
	struct reasm_frag_entry *cur, *next;

	/*
	 * When a fragment is inserted into the list, different cases can occur
	 * concerning the number of holes.
	 * - The new fragment can be inserted in the middle of a hole, such that
	 *   it will split the hole in two. The number of holes increases by 1.
	 * - The new fragment can be attached to one end of a hole, such that
	 *   the rest of the hole remains at the opposite side of the fragment.
	 *   The number of holes remains constant.
	 * - The new fragment can fill a hole completely. The number of holes
	 *   decreases by 1.
	 */

	/*
	 * If more fragments follow and the payload size is not an integer
	 * multiple of 8, the packet will never be reassembled completely.
	 */
	if (!last_frag && (frag->len & 7) != 0)
		return false;

	if (entry->len != 0 && frag->len + frag->offset > entry->len)
		return false; /* fragment extends past end of packet */

	fit_left = false;
	fit_right = false;

	if (last_frag) {
		if (entry->len != 0)
			return false;
		entry->len = frag->offset + frag->len;
		fit_right = true;
	}

	cur = entry->frags;
	next = cur->next;

	while (cur->next != NULL && cur->next->offset <= frag->offset)
		cur = cur->next;
	next = cur->next;

	/* Fragment is to be inserted between cur and next; next may be NULL. */

	/* Overlap checks. */
	if (cur->offset + cur->len > frag->offset)
		return false; /* overlaps with cur */
	else if (cur->offset + cur->len == frag->offset)
		fit_left = true;

	if (next != NULL) {
		if (last_frag)
			return false; /* next extends past end of packet */
		if (frag->offset + frag->len > next->offset)
			return false; /* overlaps with next */
		else if (frag->offset + frag->len == next->offset)
			fit_right = true;
	}

	/*
	 * Everything's fine, insert it.
	 */
	if (frag->len != 0) {
		frag->next = cur->next;
		cur->next = frag;

		if (fit_left && fit_right)
			entry->holes--;
		else if (!fit_left && !fit_right)
			entry->holes++;

		entry->frag_count++;
	} else {
		/*
		 * If the fragment has zero size, we don't insert it into the list,
		 * but one case remains to be handled: If the zero-size fragment
		 * is the last fragment, and fits exactly with the fragment to its
		 * left, the number of holes decreases.
		 */
		if (last_frag && fit_left)
			entry->holes--;
	}


	return true;
}


struct reasm_ip *
reasm_ip_new (void)
{
	struct reasm_ip *reasm = malloc (sizeof (*reasm));
	if (reasm == NULL)
		return NULL;

	memset (reasm, 0, sizeof (*reasm));
	return reasm;
}


void
reasm_ip_free (struct reasm_ip *reasm)
{
	while (reasm->time_first != NULL)
		drop_entry (reasm, reasm->time_first);
	free (reasm);
}


static bool
is_complete (struct reasm_ip_entry *entry)
{
	return entry->holes == 0;
}


static void
assemble (struct reasm_ip_entry *entry, unsigned char *out_packet, unsigned *output_len)
{
	struct reasm_frag_entry *frag = entry->frags->next; /* skip list head */
	unsigned offset0 = frag->data_offset;

	switch (entry->protocol) {
		case PROTO_IPV4:
			break;
		case PROTO_IPV6:
			offset0 -= 8; /* size of frag header */
			break;
		default:
			abort ();
	}

	if (entry->len + offset0 > *output_len) {
		/* The output buffer is too small. */
		*output_len = 0;
		return;
	}

	*output_len = entry->len + offset0;

	/* copy the (unfragmentable) header from the first fragment received */
	memcpy (out_packet, frag->data, offset0);

	/* join all the payload fragments together */
	while (frag != NULL) {
		memcpy (out_packet + offset0 + frag->offset, frag->data + frag->data_offset, frag->len);
		frag = frag->next;
	}

	/* some cleanups, e.g. update the length field of reassembled packet */
	switch (entry->protocol) {
		case PROTO_IPV4: {
			struct ip *ip_header = (struct ip *) out_packet;
			unsigned i, hl = 4 * ip_header->ip_hl;
			int32_t sum = 0;
			ip_header->ip_len = htons (offset0 + entry->len);
			ip_header->ip_off = 0;
			ip_header->ip_sum = 0;

			/* Recompute checksum. */
			for (i = 0; i < hl; i += 2) {
				uint16_t cur = (uint16_t) out_packet[i] << 8 | out_packet[i + 1];
				sum += cur;
				if ((sum & 0x80000000) != 0)
					sum = (sum & 0xffff) + (sum >> 16);
			}
			while ((sum >> 16) != 0)
				sum = (sum & 0xffff) + (sum >> 16);
			ip_header->ip_sum = htons (~sum);
			break;
		}
		case PROTO_IPV6: {
			struct ip6_hdr *ip6_header = (struct ip6_hdr *) out_packet;
			ip6_header->ip6_plen = htons (offset0 + entry->len - 40);
			break;
		}
		default:
			abort ();
	}
}


static void
drop_entry (struct reasm_ip *reasm, struct reasm_ip_entry *entry)
{
	if (entry->prev != NULL)
		entry->prev->next = entry->next;
	else
		reasm->table[entry->hash] = entry->next;

	if (entry->next != NULL)
		entry->next->prev = entry->prev;

	if (entry->time_prev != NULL)
		entry->time_prev->time_next = entry->time_next;
	else
		reasm->time_first = entry->time_next;

	if (entry->time_next != NULL)
		entry->time_next->time_prev = entry->time_prev;
	else
		reasm->time_last = entry->time_prev;

	reasm->waiting--;

	free_entry (entry);
}


static void
free_entry (struct reasm_ip_entry *entry)
{
	struct reasm_frag_entry *frag = entry->frags, *next;
	while (frag != NULL) {
		next = frag->next;
		if (frag->data != NULL)
			free (frag->data);
		free (frag);
		frag = next;
	}

	free (entry);
}


unsigned
reasm_ip_waiting (const struct reasm_ip *reasm)
{
	return reasm->waiting;
}


unsigned
reasm_ip_max_waiting (const struct reasm_ip *reasm)
{
	return reasm->max_waiting;
}


unsigned
reasm_ip_timed_out (const struct reasm_ip *reasm)
{
	return reasm->timed_out;
}


unsigned
reasm_ip_dropped_frags (const struct reasm_ip *reasm)
{
	return reasm->dropped_frags;
}


bool
reasm_ip_set_timeout (struct reasm_ip *reasm, reasm_time_t timeout)
{
	if (reasm->time_first != NULL)
		return false;

	reasm->timeout = timeout;
	return true;
}


static void
process_timeouts (struct reasm_ip *reasm, reasm_time_t now)
{
	while (reasm->time_first != NULL && reasm->time_first->timeout < now) {
		reasm->timed_out++;
		drop_entry (reasm, reasm->time_first);
	}
}


static struct reasm_frag_entry *
frag_from_ipv6 (const unsigned char *packet, unsigned frag_hdr_offset, uint32_t *ip_id, bool *last_frag)
{
	const struct ip6_hdr *ip6_header = (const struct ip6_hdr *) packet;
	unsigned offset = 40; /* IPv6 header size */
	uint8_t nxt = ip6_header->ip6_nxt;
	unsigned total_len = 40 + ntohs (ip6_header->ip6_plen);
	unsigned last_nxt = offsetof (struct ip6_hdr, ip6_nxt);
	struct reasm_frag_entry *frag;
	const struct ip6_frag *frag_header;
	unsigned char *frag_data;

	/*
	 * IPv6 extension headers from RFC 2460:
	 *   0 Hop-by-Hop Options
	 *  43 Routing
	 *  44 Fragment
	 *  60 Destination Options
	 *
	 * We look out for the Fragment header; the other 3 header
	 * types listed above are recognized and considered safe to
	 * skip over if they occur before the Fragment header.
	 * Any unrecognized header will cause processing to stop and
	 * a subsequent Fragment header to stay unrecognized.
	 */
	if (frag_hdr_offset != 0)
		offset = frag_hdr_offset;
	else {
		while (nxt == IPPROTO_HOPOPTS || nxt == IPPROTO_ROUTING || nxt == IPPROTO_DSTOPTS) {
			unsigned exthdr_len;

			if (offset + 2 > total_len)
				return NULL;  /* header extends past end of packet */

			exthdr_len = 8 + 8 * packet[offset + 1];
			if (offset + exthdr_len > total_len)
				return NULL;  /* header extends past end of packet */

			nxt = packet[offset];
			last_nxt = offset;
			offset += exthdr_len;
		}

		if (nxt != IPPROTO_FRAGMENT)
			return NULL;
	}

	if (offset + 8 > total_len)
		return NULL;  /* Fragment header extends past end of packet */

	frag = malloc (sizeof (*frag));
	if (frag == NULL)
		abort ();

	frag_header = (const struct ip6_frag *) (packet + offset);
	offset += 8;

	frag_data = malloc (total_len);
	if (frag_data == NULL)
		abort ();
	memcpy (frag_data, packet, total_len);

	/*
	 * The Fragment header will be removed on reassembly, so we have to
	 * replace the Next Header field of the previous header (which is
	 * currently IPPROTO_FRAGMENT), with the Next Header field of the
	 * Fragment header.
	 *
	 * XXX We really shouldn't manipulate the input packet in-place.
	 */
	frag_data[last_nxt] = frag_header->ip6f_nxt;

	memset(frag, 0, sizeof *frag);
	frag->len = total_len - offset;
	frag->data_offset = offset;
	frag->offset = ntohs (frag_header->ip6f_offlg & IP6F_OFF_MASK);
	frag->data = frag_data;

	*ip_id = ntohl (frag_header->ip6f_ident);
	*last_frag = (frag_header->ip6f_offlg & IP6F_MORE_FRAG) == 0;

	return frag;
}


static bool
reasm_id_equal (enum reasm_proto proto, const union reasm_id *left, const union reasm_id *right)
{
	switch (proto) {
		case PROTO_IPV4:
			return memcmp (left->ipv4.ip_src, right->ipv4.ip_src, 4) == 0
				&& memcmp (left->ipv4.ip_dst, right->ipv4.ip_dst, 4) == 0
				&& left->ipv4.ip_id == right->ipv4.ip_id
				&& left->ipv4.ip_proto == right->ipv4.ip_proto;
		case PROTO_IPV6:
			return memcmp (left->ipv6.ip_src, right->ipv6.ip_src, 16) == 0
				&& memcmp (left->ipv6.ip_dst, right->ipv6.ip_dst, 16) == 0
				&& left->ipv6.ip_id == right->ipv6.ip_id;
		default:
			abort ();
	}
}


static struct reasm_frag_entry *
parse_packet (const unsigned char *packet, unsigned len, unsigned frag_hdr_offset, enum reasm_proto *protocol, union reasm_id *id, unsigned *hash, bool *last_frag)
{
	const struct ip *ip_header = (const struct ip *) packet;
	struct reasm_frag_entry *frag = NULL;

	switch (ip_header->ip_v) {
		case 4: {
			uint16_t offset = ntohs (ip_header->ip_off);

			*protocol = PROTO_IPV4;
			if (len >= (unsigned) ntohs (ip_header->ip_len) &&
			    (offset & (IP_MF | IP_OFFMASK)) != 0)
			{
				unsigned pl_hl, pl_len, pl_off;
				u_char *frag_data;

				frag = malloc (sizeof (*frag));
				if (frag == NULL)
					abort ();

				pl_hl = ip_header->ip_hl * 4;
				pl_len = ntohs (ip_header->ip_len);
				pl_off = (offset & IP_OFFMASK) * 8;
				frag_data = malloc (pl_len);
				if (frag_data == NULL)
					abort ();
				memcpy (frag_data, packet, pl_len);

				frag->len = pl_len - pl_hl;
				frag->offset = pl_off;
				frag->data_offset = ip_header->ip_hl * 4;
				frag->data = frag_data;

				*last_frag = (offset & IP_MF) == 0;

				memcpy (id->ipv4.ip_src, &ip_header->ip_src, 4);
				memcpy (id->ipv4.ip_dst, &ip_header->ip_dst, 4);
				id->ipv4.ip_id = ntohs (ip_header->ip_id);
				id->ipv4.ip_proto = ip_header->ip_p;

				*hash = reasm_ipv4_hash (&id->ipv4);
			}
			break;
		}

		case 6: {
			const struct ip6_hdr *ip6_header =
				(const struct ip6_hdr *) packet;
			*protocol = PROTO_IPV6;
			if (len >= (unsigned) ntohs (ip6_header->ip6_plen) + 40)
				frag = frag_from_ipv6 (packet, frag_hdr_offset, &id->ipv6.ip_id, last_frag);
			if (frag != NULL) {
				memcpy (id->ipv6.ip_src, &ip6_header->ip6_src, 16);
				memcpy (id->ipv6.ip_dst, &ip6_header->ip6_dst, 16);
				*hash = reasm_ipv6_hash (&id->ipv6);
			}
			break;
		}

		default:
			break;
	}

	return frag;
}
