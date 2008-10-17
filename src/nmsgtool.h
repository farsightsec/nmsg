#ifndef NMSGTOOL_H
#define NMSGTOOL_H

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

#include "argv.h"

/* Data structures. */

struct nmsgtool_bufsink {
	ISC_LINK(struct nmsgtool_bufsink)  link;
	nmsg_buf	buf;
	time_t		embargo;
	unsigned	count;
	unsigned	freq;
	unsigned	rate;
};
typedef struct nmsgtool_bufsink nmsgtool_bufsink;

struct nmsgtool_bufsource {
	ISC_LINK(struct nmsgtool_bufsource)  link;
	nmsg_buf	buf;
};
typedef struct nmsgtool_bufsource nmsgtool_bufsource;

typedef struct {
	/* parameters */
	argv_array_t	socksinks;
	bool		help;
	char *		endline;
	char *		mname;
	char *		vname;
	char *		r_nmsg;
	char *		r_pres;
	char *		w_nmsg;
	char *		w_pres;
	int		debug;

	/* state */
	FILE *		fp_w_pres;
	ISC_LIST(struct nmsgtool_bufsink)  bufsinks;
	ISC_LIST(struct nmsgtool_bufsource)  bufsources;
	ProtobufCAllocator  ca;
	ProtobufCAllocator  modca;
	int		fd_r_nmsg, fd_r_pres;
	int		fd_w_nmsg, fd_w_pres;
	int		n_r_nmsg, n_r_pres;
	int		n_w_nmsg, n_w_pres;
	nmsg_fma	fma;
	nmsg_pbmodset	ms;
	uint64_t	count_total;
	unsigned	msgtype;
	unsigned	vendor;
} nmsgtool_ctx;

void usage(const char *msg);

#endif
