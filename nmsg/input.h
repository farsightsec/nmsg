/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#ifndef NMSG_INPUT_H
#define NMSG_INPUT_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/input.h
 * \brief Convert input streams to nmsg format.
 *
 * Nmsg containers are read and deserialized from a file descriptor and
 * can be returned to the caller, or a callback can be provided for
 * handling individual payloads.
 *
 * Presentation format data is read from a file descriptor and, if an
 * appropriate module is found to handle the presentation format, may be
 * converted to the nmsg format.
 *
 * \li MP:
 *	Clients must ensure synchronized access when reading from an
 *	nmsg_buf object.
 *
 * \li Reliability:
 *	Clients must not touch the underlying file descriptor.
 *
 * \li Resources:
 *	A small buffer will be used until an nmsg_buf object is destroyed.
 */

/***
 *** Imports
 ***/

#include <nmsg.h>
#include <nmsg/datagram.h>
#include <pcap.h>

/***
 *** Types
 ***/

typedef void (*nmsg_cb_payload)(Nmsg__NmsgPayload *np, void *user);
/*%< 
 * A function used to process an incoming nmsg payload.
 *
 * Ensures:
 *
 * \li	'np' is a valid nmsg payload.
 *
 * \li	'user' is the user-provided pointer provided to nmsg_input_loop().
 */

/***
 *** Functions
 ***/

nmsg_buf
nmsg_input_open_file(int fd);
/*%<
 * Initialize a new nmsg_buf input from a byte-stream source.
 *
 * Requires:
 *
 * \li	'fd' is a valid readable file descriptor from a byte-stream source.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_buf
nmsg_input_open_sock(int fd);
/*%<
 * Initialize a new nmsg_buf input from a datagram socket source.
 *
 * Requires:
 *
 * \li	'fd' is a valid readable file descriptor from a datagram socket
 *	source.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_pcap
nmsg_input_open_pcap(pcap_t *phandle);
/*%<
 * Initialize a new nmsg_buf input from a libpcap source.
 *
 * Requires:
 *
 * \li	'phandle' is a valid pcap_t handle
 *	(e.g., acquired from pcap_open_offline())
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_pres
nmsg_input_open_pres(int fd, unsigned vid, unsigned msgtype);
/*%<
 * Initialize a new nmsg_pres input.
 *
 * Requires:
 *
 * \li	'fd' is a valid file descriptor.
 *
 * \li	'vid' is a known vendor ID.
 *
 * \li	'msgtype' is a known vendor-specific message type.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_res
nmsg_input_close(nmsg_buf *buf);
/*%<
 * Close an nmsg_buf input.
 *
 * Requires:
 *
 * \li	'*buf' is a valid pointer to an nmsg_buf object.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 *
 * Ensures:
 *
 * \li	'buf' will be NULL on return, and all associated resources will be
 * freed.
 */

nmsg_res
nmsg_input_close_pcap(nmsg_pcap *pcap);

nmsg_res
nmsg_input_loop(nmsg_buf buf, int count, nmsg_cb_payload cb, void *user);
/*%<
 * Loop over the nmsg containers in an input stream and call a user-provided
 * closure for each payload.
 *
 * Requires:
 *
 * \li	'buf' is a valid nmsg_buf.
 *
 * \li	'count' is non-negative to indicate a finite number of containers to
 *	process, or negative to indicate all available containers should be
 *	processed.
 *
 * \li	'cb' is a non-NULL function pointer.
 *
 * \li	'user' is an optionally NULL pointer which will be passed to the
 *	callback.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	any of nmsg_input_next()'s return values
 */

nmsg_res
nmsg_input_next(nmsg_buf buf, Nmsg__Nmsg **nmsg);
/*%<
 * Read one nmsg payload container from an input stream.
 *
 * Requires:
 *
 * \li	'buf' is a valid nmsg_buf.
 *
 * \li	'**nmsg' is a pointer to where an Nmsg__Nmsg pointer may be stored.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 * \li	nmsg_res_again
 * \li	nmsg_res_eof
 * \li	nmsg_res_magic_mismatch
 * \li	nmsg_res_version_mismatch
 */

nmsg_res
nmsg_input_next_pcap(nmsg_pcap pcap, struct nmsg_datagram **dg);

#endif /* NMSG_INPUT_H */
