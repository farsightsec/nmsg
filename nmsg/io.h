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

#include <sys/types.h>

#include <nmsg.h>
#include <nmsg/nmsg.pb-c.h>
#include <nmsg/res.h>

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
	nmsg_io_close_type	closetype;
	nmsg_io_fd_type		fdtype;
	void			*user;
};

typedef void (*nmsg_io_closed_fp)(nmsg_io, struct nmsg_io_close_event *);

nmsg_io
nmsg_io_init(nmsg_pbmodset, size_t max);

nmsg_res
nmsg_io_add_buf(nmsg_io, nmsg_buf, void *);

nmsg_res
nmsg_io_add_pres(nmsg_io, nmsg_pres, nmsg_pbmod, void *);

nmsg_res
nmsg_io_loop(nmsg_io);

void
nmsg_io_breakloop(nmsg_io);

void
nmsg_io_destroy(nmsg_io *);

void
nmsg_io_set_closed_fp(nmsg_io, nmsg_io_closed_fp);

void
nmsg_io_set_count(nmsg_io, unsigned);

void
nmsg_io_set_debug(nmsg_io, int);

void
nmsg_io_set_endline(nmsg_io, const char *);

void
nmsg_io_set_interval(nmsg_io, unsigned);

void
nmsg_io_set_output_mode(nmsg_io, nmsg_io_output_mode);

#endif
