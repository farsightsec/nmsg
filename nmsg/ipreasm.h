#ifndef NMSG_IPREASM_H
#define NMSG_IPREASM_H

#define reasm_time_t		nmsg_reasm_time_t
#define reasm_ip		nmsg_reasm_ip
#define reasm_ip_new		nmsg_reasm_ip_new
#define reasm_ip_free		nmsg_reasm_ip_free
#define reasm_ip_next		nmsg_reasm_ip_next
#define reasm_ip_set_timeout	nmsg_reasm_ip_set_timeout
#define reasm_ip_waiting	nmsg_reasm_ip_waiting
#define reasm_ip_max_waiting	nmsg_reasm_ip_max_waiting
#define reasm_ip_timed_out	nmsg_reasm_ip_timed_out
#define reasm_ip_dropped_frags	nmsg_reasm_ip_dropped_frags

/*
 * Copyright (c) 2007  Jan Andres <jandres@gmx.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <arpa/inet.h>
#include <stdbool.h>

/*
 * This is an abstract time stamp. ipreasm doesn't care whether it is
 * in seconds, milliseconds, or nanodecades. All it does it add the
 * configured timeout value to it, and then compare it to the timstamps
 * of subsequent packets to decide whether a fragment has expired.
 */
typedef uint64_t reasm_time_t;

struct reasm_ip;

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
 * If frag_hdr_offset is not zero, for IPv6 packets, it specifies the
 * offset into the packet at which the fragment header starts.
 */
bool reasm_ip_next (struct reasm_ip *reasm, const unsigned char *packet,
		    unsigned len, unsigned frag_hdr_offset,
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

#endif /* NMSG_IPREASM_H */
