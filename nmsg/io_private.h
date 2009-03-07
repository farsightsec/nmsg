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

#ifndef NMSG_IO_PRIVATE_H
#define NMSG_IO_PRIVATE_H

/* Import. */

#include "nmsg_port.h"

#include <stdio.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "io.h"
#include "private.h"
#include "pbmod.h"
#include "pbmodset.h"

/* Data structures. */

struct nmsg_io_pres {
	ISC_LINK(struct nmsg_io_pres)	link;
	FILE				*fp;
	nmsg_pbmod			mod;
	nmsg_pres			pres;
	pthread_mutex_t			lock;
	struct timespec			last;
	void				*clos, *user;
	uint64_t			count_payload_out;
};

struct nmsg_io_buf {
	ISC_LINK(struct nmsg_io_buf)	link;
	nmsg_buf			buf;
	pthread_mutex_t			lock;
	struct timespec			last;
	void				*user;
	uint64_t			count_payload_out;
};

struct nmsg_io_pcap {
	ISC_LINK(struct nmsg_io_pcap)	link;
	nmsg_pbmod			mod;
	nmsg_pcap			pcap;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_buf)	r_nmsg;
	ISC_LIST(struct nmsg_io_buf)	w_nmsg;
	ISC_LIST(struct nmsg_io_pres)	r_pres;
	ISC_LIST(struct nmsg_io_pres)	w_pres;
	ISC_LIST(struct nmsg_io_pcap)	r_pcap;
	ISC_LIST(struct nmsg_io_thr)	iothreads;
	bool				quiet, zlibout;
	char				*endline;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	nmsg_io_output_mode		output_mode;
	nmsg_pbmodset			ms;
	pthread_mutex_t			lock;
	uint64_t			count_pres_out, count_pres_payload_out;
	uint64_t			count_nmsg_out, count_nmsg_payload_out;
	unsigned			count, interval;
	unsigned			n_user, user[2];
	volatile bool			stop, stopped;
};

struct nmsg_io_thr {
	ISC_LINK(struct nmsg_io_thr)	link;
	pthread_t			thr;
	nmsg_io				io;
	nmsg_res			res;
	struct timespec			now;
	union {
		struct nmsg_io_buf	*iobuf;
		struct nmsg_io_pres	*iopres;
		struct nmsg_io_pcap	*iopcap;
	};
	union {
		uint64_t		count_nmsg_in;
		uint64_t		count_pres_in;
		uint64_t		count_pcap_in;
	};
	union {
		uint64_t		count_nmsg_payload_in;
		uint64_t		count_pres_payload_in;
		uint64_t		count_pcap_datagram_in;
	};
};

/* Export. */

void *
_nmsg_io_thr_nmsg_read(void *);

void *
_nmsg_io_thr_pres_read(void *);

void *
_nmsg_io_thr_pcap_read(void *);

Nmsg__NmsgPayload *
_nmsg_io_make_nmsg_payload(struct nmsg_io_thr *, uint8_t *, size_t,
			   unsigned, unsigned);

nmsg_res
_nmsg_io_write_nmsg(struct nmsg_io_thr *, struct nmsg_io_buf *, Nmsg__Nmsg *);

nmsg_res
_nmsg_io_write_nmsg_dup(struct nmsg_io_thr *, struct nmsg_io_buf *,
			const Nmsg__Nmsg *);

nmsg_res
_nmsg_io_write_nmsg_payload(struct nmsg_io_thr *, struct nmsg_io_buf *,
			    Nmsg__NmsgPayload *);

nmsg_res
_nmsg_io_write_pres(struct nmsg_io_thr *, struct nmsg_io_pres *,
		    const Nmsg__Nmsg *);

nmsg_res
_nmsg_io_write_pres_payload(struct nmsg_io_thr *, struct nmsg_io_pres *,
			    Nmsg__NmsgPayload *);

#endif /* NMSG_IO_PRIVATE_H */
