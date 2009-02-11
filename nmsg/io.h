/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#ifndef NMSG_IO_H
#define NMSG_IO_H

/*****
 ***** Module Info
 *****/

/*! file nmsg/io.h
 * \brief Multi-threaded nmsg I/O processing.
 *
 * nmsg_io objects handle the multiplexing of nmsg data between nmsg_buf
 * and nmsg_pres objects. Callers should initialize at least one input and
 * at least one output and add them to an nmsg_io object before calling
 * nmsg_io_loop().
 *
 * \li MP:
 *	One thread is created to handle reading from each input.
 *	nmsg_io_loop() will block until all data has been processed, but
 *	callers should take care not to touch an nmsg_io object (or any of
 *	its constituent input or output objects) asychronously while
 *	nmsg_io_loop() is executing, with the exception of
 *	nmsg_io_breakloop() which may be called asynchronously to abort the
 *	loop.
 */

/***
 *** Imports
 ***/

#include <nmsg.h>
#include <nmsg/res.h>
#include <nmsg/pbmodset.h>

/***
 *** Types
 ***/

typedef struct nmsg_io *nmsg_io;

typedef enum {
	nmsg_io_close_type_eof,
	nmsg_io_close_type_count,
	nmsg_io_close_type_interval
} nmsg_io_close_type;

typedef enum {
	nmsg_io_fd_type_input_nmsg,
	nmsg_io_fd_type_input_pres,
	nmsg_io_fd_type_output_nmsg,
	nmsg_io_fd_type_output_pres
} nmsg_io_fd_type;

typedef enum {
	nmsg_io_output_mode_stripe,
	nmsg_io_output_mode_mirror
} nmsg_io_output_mode;

struct nmsg_io_close_event {
	union {
		nmsg_pres	*pres;
		nmsg_buf	*buf;
	};
	nmsg_io			io;
	nmsg_io_close_type	closetype;
	nmsg_io_fd_type		fdtype;
	void			*user;
};

typedef void (*nmsg_io_closed_fp)(struct nmsg_io_close_event *);

/***
 *** Functions
 ***/

nmsg_io
nmsg_io_init(nmsg_pbmodset ms);
/*%<
 * Initialize a new nmsg_io context.
 *
 * Requires:
 *
 * \li	'ms' is an nmsg_pbmodset instance, or NULL if the caller does not
 *	add a presentation format output.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_res
nmsg_io_add_buf(nmsg_io io, nmsg_buf buf, void *user);
/*%<
 * Add an input or output buffer to the nmsg_io context.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'buf' is a valid readable or writable nmsg_buf object.
 *
 * \li	'user' is a pointer associated with 'buf' that will be passed to a
 *	close event notification function if close notification is in use.
 *	If 'user' is non-NULL, nmsg_io_set_closed_fp() must be called with
 *	valid non-NULL arguments.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_memfail
 */

nmsg_res
nmsg_io_add_pres(nmsg_io io, nmsg_pres pres, nmsg_pbmod pbmod, void *user);
/*%<
 * Add an input or output presentation format stream to the nmsg_io
 * context.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'pres' is a valid nmsg_pres object.
 * 
 * \li	'pbmod' is a valid nmsg_pbmod module if 'pres' is an input
 *	nmsg_pres, NULL otherwise.
 *
 * \li	'user' is a pointer associated with 'pres' that will be passed to a
 *	close event notification function if close notification is in use.
 *	If 'user' is non-NULL, nmsg_io_set_closed_fp() must be called with
 *	valid non-NULL arguments.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_memfail
 */

nmsg_res
nmsg_io_loop(nmsg_io io);
/*%<
 * Begin processing the data specified by the configured inputs and
 * outputs.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 *
 * Notes:
 *
 * \li	nmsg_io_loop() invalidates an nmsg_io context.
 *
 * \li	One processing thread is created for each input. nmsg_io_loop()
 *	return until these threads finish and are destroyed.
 *
 * \li	Only nmsg_io_breakloop() may be called asynchronously while
 *	nmsg_io_loop() is executing.
 */

void
nmsg_io_breakloop(nmsg_io io);
/*%<
 * Break a currently executing nmsg_io_loop().
 *
 * Requires:
 *
 * \li	'io' is a valid and currently processing nmsg_io context.
 *
 * Notes:
 *
 * \li	Since nmsg_io_loop() is a blocking call, nmsg_io_breakloop() must
 *	be called asynchronously.
 */

void
nmsg_io_destroy(nmsg_io *io);
/*%<
 * Deallocate the resources associated with an nmsg_io context.
 *
 * Requires:
 *
 * \li	'io' is a pointer to an nmsg_io context.
 */

void
nmsg_io_set_closed_fp(nmsg_io io, nmsg_io_closed_fp closed_fp);
/*%<
 * Set the close event notification function associated with an nmsg_io
 * context.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'closed_fp' is a pointer to an nmsg_io_closed_fp function. It must
 *	be reentrant.
 *
 * Notes:
 *
 * \li	'closed_fp' will only be called at EOF on an input or output
 *	stream, unless nmsg_io_set_count() or nmsg_io_set_interval() are
 *	used to specify conditions when an input stream should be closed.
 */

void
nmsg_io_set_count(nmsg_io io, unsigned count);
/*%<
 * Configure the nmsg_io context to close inputs after processing 'count'
 * payloads.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'count' > 0
 *
 * Notes:
 *
 * \li	If the 'user' pointer associated with an input stream is non-NULL
 *	(see nmsg_io_add_buf() and nmsg_io_add_pref()) the close event
 *	notification function must be set, and this function must reopen
 *	the stream. If the 'user' pointer is NULL, nmsg_io processing will
 *	be shut down.
 */

void
nmsg_io_set_debug(nmsg_io io, int debug);
/*%<
 * Set the debug level for an nmsg_io context.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'debug' >= 0. debug levels greater than zero result in the logging
 *	of debug info.
 */

void
nmsg_io_set_endline(nmsg_io io, const char *e);
/*%<
 * Set the line continuation string for presentation format output.  The
 * default is "\\\n".
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'e' is a valid character string.
 */

void
nmsg_io_set_interval(nmsg_io io, unsigned interval);
/*%<
 * Configure the nmsg_io context to close inputs after processing for
 * 'interval' seconds.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'interval' > 0
 *
 * Notes:
 *
 * \li	If the 'user' pointer associated with an input stream is non-NULL
 *	(see nmsg_io_add_buf() and nmsg_io_add_pref()) the close event
 *	notification function must be set, and this function must reopen
 *	the stream. If the 'user' pointer is NULL, nmsg_io processing will
 *	be shut down.
 */

void
nmsg_io_set_quiet(nmsg_io io, bool quiet);
/*%<
 * Set quiet presentation output mode, i.e. suppress headers and only
 * output raw presentation payloads.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'quiet' is true or false.
 */

void
nmsg_io_set_output_mode(nmsg_io io, nmsg_io_output_mode output_mode);
/*%<
 * Set the output mode behavior for an nmsg_io context. Nmsg payloads
 * received from inputs may be striped across available outputs (the
 * default), or mirrored across all available outputs.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'output_mode' is nmsg_io_output_mode_stripe or
 *	nmsg_io_output_mode_mirror.
 *
 * Notes:
 *
 * \li	Since nmsg_io must synchronize access to individual outputs, the
 *	mirrored output mode will limit the amount of parallelism that can
 *	be achieved.
 */

void
nmsg_io_set_user(nmsg_io io, unsigned pos, unsigned user);
/*%<
 * Set one of the two unsigned 32 bit 'user' fields in output nmsg
 * payloads.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'pos' is 0 or 1.
 *
 * \li	'user' is a 32 bit quantity.
 */

void
nmsg_io_set_zlibout(nmsg_io io, bool zlibout);
/*%<
 * Set nmsg output compression mode, i.e. perform zlib compression on
 * output nmsg containers if set to true.
 *
 * Requires:
 *
 * \li	'io' is a valid nmsg_io context.
 *
 * \li	'zlibout' is true or false.
 */

#endif /* NMSG_IO_H */
