#ifndef NMSG_ISC_IPREASM_H
#define NMSG_ISC_IPREASM_H

/*
 * Copyright (c) 2007  Jan Andres <jandres@gmx.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct reasm_ip;

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
	uint8_t ip_src[4];
	uint8_t ip_dst[4];
	uint16_t ip_id;
	uint8_t ip_proto;
};

/*
 * Same for IPv6.
 */
struct reasm_id_ipv6 {
	uint8_t ip_src[16];
	uint8_t ip_dst[16];
	uint32_t ip_id;
};

union reasm_id {
	struct reasm_id_ipv4 ipv4;
	struct reasm_id_ipv6 ipv6;
};

struct reasm_frag_entry {
	struct timespec ts;
	unsigned len;  /* payload length of this fragment */
	unsigned offset; /* offset of this fragment into the payload of the reassembled packet */
	unsigned data_offset; /* offset to the data pointer where payload starts */
	unsigned last_nxt;
	unsigned ip6f_nxt;
	uint8_t *data; /* payload starts at data + data_offset */
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
	unsigned len;
	unsigned holes;
	unsigned frag_count;
	unsigned hash;
	struct timespec timeout;
	enum entry_state state;
	enum reasm_proto protocol;
	struct reasm_frag_entry *frags;
	struct reasm_ip_entry *prev, *next;
	struct reasm_ip_entry *time_prev, *time_next;
};

/*
 * Functions to create and destroy the reassembly environment.
 */
struct reasm_ip *reasm_ip_new(void);
void reasm_ip_free(struct reasm_ip *reasm);

/*
 * This is the main packet processing function. It inputs one packet,
 * and MAY output one packet in turn. If the input was not a fragment,
 * no output is generated, and false is returned. If the input was a
 * fragment, true is returned.
 * The unsigned pointed to by output_len should initially be set to the
 * size of the buffer behind out_packet. On return, it will be set to
 * the length of the packet returned, or 0 if no packet was returned
 * (this will happen if a fragment is recognized, but reassembly of the
 * corresponding packet has not completed yet).
 */
bool reasm_ip_next(struct reasm_ip *reasm, const uint8_t *packet, unsigned len,
		   const struct timespec *timestamp, struct reasm_ip_entry **out_entry);

/*
 * Create fragment structure from an IPv4 or IPv6 packet. Returns NULL
 * if the input is not a fragment.
 *
 * \param[in] packet
 * \param[in] len
 * \param[in] ts
 * \param[out] protocol
 * \param[out] id
 * \param[out] hash
 * \param[out] last_frag
 */
struct reasm_frag_entry *reasm_parse_packet(const uint8_t *packet, unsigned len,
					    const struct timespec *ts,
					    enum reasm_proto *protocol, union reasm_id *id,
					    unsigned *hash, bool *last_frag);

/*
 * Set the timeout after which a noncompleted reassembly expires.
 */
bool reasm_ip_set_timeout(struct reasm_ip *reasm, const struct timespec *timeout);

/*
 * Query certain information about the current state.
 */
unsigned reasm_ip_waiting(const struct reasm_ip *reasm);
unsigned reasm_ip_max_waiting(const struct reasm_ip *reasm);
unsigned reasm_ip_timed_out(const struct reasm_ip *reasm);
unsigned reasm_ip_dropped_frags(const struct reasm_ip *reasm);

/*
 * Is the entry complete, ready for reassembly?
 */
bool reasm_is_complete(struct reasm_ip_entry *entry);

/*
 * Create the reassembled packet.
 *
 * \param[in] entry
 * \param[out] out_packet
 * \param[in,out] output_len
 */
void reasm_assemble(struct reasm_ip_entry *entry,
		    uint8_t *out_packet, size_t *output_len);

/*
 * Insert a new fragment to the correct position in the list of fragments.
 * Check for fragment overlap and other error conditions.
 */
bool reasm_add_fragment(struct reasm_ip_entry *entry,
			struct reasm_frag_entry *frag,
			bool last_frag);

void reasm_free_entry(struct reasm_ip_entry *entry);

#endif /* NMSG_ISC_IPREASM_H */
