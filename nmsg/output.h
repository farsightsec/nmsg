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

#ifndef NMSG_OUTPUT_H
#define NMSG_OUTPUT_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/output.h
 * \brief Write nmsg containers to output streams.
 *
 * Nmsg payloads can buffered and written to a file descriptor, or
 * converted to presentation format and written to a file descriptor.
 *
 * \li MP:
 *	Clients must ensure synchronized access when writing to an nmsg_buf
 *	object.
 *
 * \li Reliability:
 *	Clients must not touch the underlying file descriptor.
 */

/***
 *** Imports
 ***/

#include "nmsg_port.h"

#include <sys/types.h>

#include <nmsg.h>
#include <nmsg/nmsg.pb-c.h>
#include <nmsg/rate.h>
#include <nmsg/res.h>

/***
 *** Functions
 ***/

nmsg_buf
nmsg_output_open_file(int fd, size_t bufsz);
/*%<
 * Initialize a new nmsg_buf output.
 *
 * Requires:
 *
 * \li	'fd' is a valid writable file descriptor.
 *
 * \li	'bufsz' is a value between NMSG_WBUFSZ_MIN and NMSG_WBUFSZ_MAX.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 *
 * Notes:
 *
 * \li	For efficiency reasons, files should probably be opened with a
 *	bufsz of NMSG_WBUFSZ_MAX.
 *
 * \li	The bufsz also affects the maximum size of an nmsg payload.
 */

nmsg_buf
nmsg_output_open_sock(int fd, size_t bufsz);
/*%<
 * Initialize a new nmsg_buf output.
 *
 * Requires:
 *
 * \li	'fd' is a valid writable socket file descriptor.
 *
 * \li	'bufsz' is a value between NMSG_WBUFSZ_MIN and NMSG_WBUFSZ_MAX.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 *
 * Notes:
 *
 * \li	For UDP sockets which are physically transported over an Ethernet,
 *	NMSG_WBUFSZ_ETHER or NMSG_WBUFSZ_JUMBO (for jumbo frame Ethernets)
 *	should be used for bufsz.
 */

nmsg_pres
nmsg_output_open_pres(int fd, int flush);
/*%<
 * Initialize a new nmsg_pres output.
 *
 * Requires:
 *
 * \li	'fd' is a valid writable file descriptor.
 * \li	'flush' is positive to indicate that the output should be flushed
 *	after every bufferable write, 0 otherwise
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_res
nmsg_output_append(nmsg_buf buf, Nmsg__NmsgPayload *np);
/*%<
 * Append an nmsg payload to an nmsg_buf output.
 *
 * Requires:
 * 
 * \li	'buf' is a valid writable nmsg_buf.
 *
 * \li	'np' is a valid nmsg payload to be serialized.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 * \li	nmsg_res_pbuf_written
 *
 * Notes:
 *
 * \li	Nmsg outputs are buffered, but payloads appended to an nmsg_buf are
 *	not copied for performance reasons; instead, the caller must
 *	allocate space for each payload until nmsg_res_pbuf_written is
 *	returned, which may be after many calls to nmsg_output_append().
 *	The payloads must then be deallocated. Optionally, the caller may
 *	use nmsg_output_set_allocator() to specify an allocator to be
 *	called when payloads should be freed.
 */

nmsg_res
nmsg_output_close(nmsg_buf *buf);
/*%<
 * Close an nmsg_buf output.
 *
 * Requires:
 *
 * \li	'*buf' is a valid pointer to an nmsg_buf object.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_pbuf_written
 */

void
nmsg_output_close_pres(nmsg_pres *pres);
/*%<
 * Close an nmsg_pres output.
 *
 * Requires:
 *
 * \li	'*pres' is a valid pointer to an nmsg_pres object.
 */

void
nmsg_output_set_rate(nmsg_buf buf, nmsg_rate rate);
/*%<
 * Limit the payload output rate.
 *
 * Requires:
 *
 * \li	'buf' is a valid writable nmsg_buf.
 *
 * \li	'rate' is a valid nmsg_rate object or NULL to disable rate
 *	limiting.
 */

void
nmsg_output_set_zlibout(nmsg_buf buf, bool zlibout);
/*%<
 * Enable or disable zlib compression of output nmsg containers.
 *
 * Requires:
 *
 * \li	'buf' is a valid writable nmsg_buf.
 *
 * \li	'zlibout' is true or false.
 */

#endif /* NMSG_OUTPUT_H */
