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
 *	Clients must ensure synchronized access when writing to an
 *	nmsg_output object.
 *
 * \li Reliability:
 *	Clients must not touch the underlying file descriptor.
 */

/***
 *** Imports
 ***/

#include <stdbool.h>

#include <sys/types.h>

#include <nmsg.h>

/***
 *** Enumerations
 ***/

typedef enum {
	nmsg_output_type_stream,
	nmsg_output_type_pres
} nmsg_output_type;

/***
 *** Functions
 ***/

nmsg_output_t
nmsg_output_open_file(int fd, size_t bufsz);
/*%<
 * Initialize a new nmsg_output object.
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

nmsg_output_t
nmsg_output_open_sock(int fd, size_t bufsz);
/*%<
 * Initialize a new nmsg_output object.
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

nmsg_output_t
nmsg_output_open_pres(int fd, nmsg_pbmodset_t ms);
/*%<
 * Initialize a new nmsg_pres output.
 *
 * Requires:
 *
 * \li	'fd' is a valid writable file descriptor.
 * \li	'ms' is an nmsg_pbmodset_t instance.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_res
nmsg_output_write(nmsg_output_t output, Nmsg__NmsgPayload *np);
/*%<
 * Append an nmsg payload to an nmsg_output object.
 *
 * Requires:
 * 
 * \li	'output' is a valid nmsg_output.
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
 * \li	Nmsg outputs are buffered, but payloads appended to an nmsg_output
 *	are not copied for performance reasons; instead, the caller must
 *	allocate space using malloc() for each payload until
 *	nmsg_res_pbuf_written is returned, which may be after many calls to
 *	nmsg_output_append(). The payloads will then be deallocated with the
 *	system's free().
 */

nmsg_res
nmsg_output_close(nmsg_output_t *output);
/*%<
 * Close an nmsg_output object.
 *
 * Requires:
 *
 * \li	'*output' is a valid pointer to an nmsg_output object.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_pbuf_written
 */

void
nmsg_output_set_buffered(nmsg_output_t output, bool buffered);
/*%<
 * Make an nmsg_output socket output buffered or unbuffered.
 *
 * By default, nmsg_output outputs (file and socket) are buffered.
 *
 * Requires:
 *
 * \li	'output' is an nmsg_output socket output.
 *
 * \li	'buffered' is true (buffered) or false (unbuffered).
 */

void
nmsg_output_set_rate(nmsg_output_t output, nmsg_rate_t rate);
/*%<
 * Limit the payload output rate.
 *
 * Requires:
 *
 * \li	'output' is a valid nmsg_output.
 *
 * \li	'rate' is a valid nmsg_rate object or NULL to disable rate
 *	limiting.
 */

void
nmsg_output_set_user(nmsg_output_t output, unsigned pos, unsigned user);
/*%<
 * Set one of the two unsigned 32 bit 'user' fields in output nmsg
 * payloads.
 *
 * Requires:
 *
 * \li	'output' is a valid nmsg_output.
 *
 * \li	'pos' is 0 or 1.
 *
 * \li	'user' is a 32 bit quantity.
 */

void
nmsg_output_set_endline(nmsg_output_t output, const char *endline);
/*%<
 * Set the line continuation string for presentation format output.
 * The default is "\n".
 *
 * Requires:
 *
 * \li	'output' is a valid nmsg_output.
 *
 * \li	'endline' is a valid character string.
 */

void
nmsg_output_set_zlibout(nmsg_output_t output, bool zlibout);
/*%<
 * Enable or disable zlib compression of output nmsg containers.
 *
 * Requires:
 *
 * \li	'output' is a valid nmsg_output.
 *
 * \li	'zlibout' is true (zlib enabled) or false (zlib disabled).
 */

#endif /* NMSG_OUTPUT_H */
