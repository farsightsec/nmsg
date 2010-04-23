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

/*
 * This is an abstract time stamp. ipreasm doesn't care whether it is
 * in seconds, milliseconds, or nanodecades. All it does it add the
 * configured timeout value to it, and then compare it to the timstamps
 * of subsequent packets to decide whether a fragment has expired.
 */
typedef uint64_t reasm_time_t;

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
	unsigned len;
	unsigned holes;
	unsigned frag_count;
	unsigned hash;
	reasm_time_t timeout;
	enum entry_state state;
	enum reasm_proto protocol;
	struct reasm_frag_entry *frags;
	struct reasm_ip_entry *prev, *next;
	struct reasm_ip_entry *time_prev, *time_next;
};

/*
 * Functions to create and destroy the reassembly environment.
 */
struct reasm_ip *reasm_ip_new (void);
void reasm_ip_free (struct reasm_ip *reasm);

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
bool reasm_ip_next (struct reasm_ip *reasm, const unsigned char *packet,
		    unsigned len,
		    reasm_time_t timestamp, unsigned char *out_packet,
		    unsigned *output_len);

/*
 * Set the timeout after which a noncompleted reassembly expires, in
 * abstract time units (see above for the definition of reasm_time_t).
 */
bool reasm_ip_set_timeout (struct reasm_ip *reasm, reasm_time_t timeout);

/*
 * Query certain information about the current state.
 */
unsigned reasm_ip_waiting (const struct reasm_ip *reasm);
unsigned reasm_ip_max_waiting (const struct reasm_ip *reasm);
unsigned reasm_ip_timed_out (const struct reasm_ip *reasm);
unsigned reasm_ip_dropped_frags (const struct reasm_ip *reasm);

#endif /* NMSG_ISC_IPREASM_H */
