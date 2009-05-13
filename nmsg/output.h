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

/*! \file nmsg/output.h
 * \brief Write nmsg containers to output streams.
 *
 * Nmsg payloads can be buffered and written to a file descriptor, or
 * converted to presentation format and written to a file descriptor.
 *
 * <b>MP:</b>
 *	\li Clients must ensure synchronized access when writing to an
 *	nmsg_output_t object.
 *
 * <b>Reliability:</b>
 *	\li Clients must not touch the underlying file descriptor.
 */

#include <sys/types.h>
#include <stdbool.h>

#include <nmsg.h>

/**
 * An enum identifying the underlying implementation of an nmsg_output_t object.
 * This is used for nmsg_io's close event notification.
 */
typedef enum {
	nmsg_output_type_stream,
	nmsg_output_type_pres
} nmsg_output_type;

/**
 * Initialize a new byte-stream nmsg output.
 *
 * For efficiency reasons, files should probably be opened with a bufsz of
 * #NMSG_WBUFSZ_MAX.
 *
 * \param[in] fd writable file descriptor.
 *
 * \param[in] bufsz value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_file(int fd, size_t bufsz);

/**
 * Initialize a new datagram socket nmsg output.
 *
 * For UDP sockets which are physically transported over an Ethernet,
 * #NMSG_WBUFSZ_ETHER or #NMSG_WBUFSZ_JUMBO (for jumbo frame Ethernets) should
 * be used for bufsz.
 *
 * \param[in] fd writable datagram socket.
 *
 * \param[in] bufsz value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_sock(int fd, size_t bufsz);

/**
 * Initialize a new presentation format (ASCII lines) nmsg output.
 *
 * \param[in] fd writable file descriptor.
 * \param[in] ms nmsg_pbmodset_t instance (for module functions).
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_pres(int fd, nmsg_pbmodset_t ms);

/**
 * Append an nmsg payload to an nmsg_output_t object.
 *
 * Nmsg outputs are buffered, but payloads appended to an nmsg nmsg_output_t are
 * not copied for performance reasons; instead, the caller must allocate space
 * using malloc() for each payload until #nmsg_res_nmsg_written is returned,
 * which may be after many calls to nmsg_output_write(). The payloads will then
 * be deallocated with the system's free(). Note that payloads obtained from an
 * nmsg_input_t object are allocated with malloc().
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] np nmsg payload to be serialized and appended to 'output'.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_nmsg_written
 */
nmsg_res
nmsg_output_write(nmsg_output_t output, Nmsg__NmsgPayload *np);

/**
 * Close an nmsg_output_t object.
 *
 * \param[in] output pointer to an nmsg_output_t object.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_nmsg_written
 */
nmsg_res
nmsg_output_close(nmsg_output_t *output);

/**
 * Make an nmsg_output_t socket output buffered or unbuffered.
 *
 * By default, file and socket nmsg_output_t outputs are buffered. Extremely low
 * volume output streams should probably be unbuffered to reduce latency.
 *
 * \param[in] output socket nmsg_output_t object.
 *
 * \param[in] buffered true (buffered) or false (unbuffered).
 */
void
nmsg_output_set_buffered(nmsg_output_t output, bool buffered);

/**
 * Limit the payload output rate.
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] rate nmsg_rate_t object or NULL to disable rate limiting.
 */
void
nmsg_output_set_rate(nmsg_output_t output, nmsg_rate_t rate);

/**
 * Set the line continuation string for presentation format output. The default
 * is "\n".
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] endline end-of-line character string.
 */
void
nmsg_output_set_endline(nmsg_output_t output, const char *endline);

/**
 * Set the 'source' field on all output NMSG payloads. This has no effect on
 * non-NMSG outputs.
 *
 * The source ID must be positive.
 *
 * \param[in] output NMSG stream nmsg_output_t object.
 *
 * \param[in] source source ID.
 */
void
nmsg_output_set_source(nmsg_output_t output, unsigned source);

/**
 * Set the 'operator' field on all output NMSG payloads. This has no effect on
 * non-NMSG outputs.
 *
 * The operator ID must be positive.
 *
 * \param[in] output NMSG stream nmsg_output_t object.
 *
 * \param[in] operator operator ID.
 */
void
nmsg_output_set_operator(nmsg_output_t output, unsigned operator);

/**
 * Set the 'group' field on all output NMSG payloads. This has no effect on
 * non-NMSG outputs.
 *
 * The group ID must be positive.
 *
 * \param[in] output NMSG stream nmsg_output_t object.
 *
 * \param[in] group group ID.
 */
void
nmsg_output_set_group(nmsg_output_t output, unsigned group);

/**
 * Enable or disable zlib compression of output NMSG containers.
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] zlibout true (zlib enabled) or false (zlib disabled).
 */
void
nmsg_output_set_zlibout(nmsg_output_t output, bool zlibout);

#endif /* NMSG_OUTPUT_H */
