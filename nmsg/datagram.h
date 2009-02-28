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

#ifndef NMSG_DATAGRAM_H
#define NMSG_DATAGRAM_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/datagram.h
 * \brief Datagram utility functions.
 */

/***
 *** Imports
 ***/

#include <sys/types.h>

#include <nmsg/res.h>

/***
 *** Types
 ***/

struct nmsg_datagram {
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
nmsg_datagram_find_network(struct nmsg_datagram *dg, int datalink,
			   const u_char *pkt, size_t len);
/*%<
 * Find the network header of an IP datagram and populate a struct
 * nmsg_datagram.
 *
 * Requires:
 *
 * \li	'dg' is a caller-allocated struct nmsg_datagram.
 *
 * \li	'datalink' is a valid libpcap datalink type. Supported datalink
 *	types are DLT_EN10MB and DLT_LINUX_SLL.
 *
 * \li	'pkt' is a pointer to the packet. The packet must match the
 *	specified datalink type.
 *
 * \li	'len' is the total number of octets captured in 'pkt'.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 */

nmsg_res
nmsg_datagram_find_transport(struct nmsg_datagram *dg);

nmsg_res
nmsg_datagram_find_payload(struct nmsg_datagram *dg);

bool
nmsg_datagram_is_fragment(struct nmsg_datagram *dg);

#endif /* NMSG_DATAGRAM_H */
