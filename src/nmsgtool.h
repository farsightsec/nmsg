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

/* Import. */

#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include <nmsg.h>

/* Data structures. */

struct nmsgtool_bufsink {
	ISC_LINK(struct nmsgtool_bufsink)  link;
	nmsg_buf	buf;
	unsigned	count;
	time_t		embargo;
};

struct nmsgtool_ctx {
	ISC_LIST(struct nmsgtool_bufsink)  bufsinks;
	argv_array_t	socksinks;
	bool		help;
	char *		mname;
	char *		vname;
	int		debug;
	unsigned	msgtype;
	unsigned	vendor;
	nmsg_pbmodset	ms;
};
