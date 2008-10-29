/* nmsg_io - threaded nmsg I/O interface */

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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>
#include <unistd.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "nmsg.h"
#include "nmsg_port.h"
#include "nmsg_private.h"

/* Data structures. */

struct nmsg_io_pres {
	ISC_LINK(struct nmsg_io_pres)	link;
	FILE				*fp;
	nmsg_pbmod			mod;
	nmsg_pres			pres;
	pthread_mutex_t			lock;
	void				*user;
};

struct nmsg_io_buf {
	ISC_LINK(struct nmsg_io_buf)	link;
	nmsg_buf			buf;
	pthread_mutex_t			lock;
	void				*user;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_buf)	r_nmsg;
	ISC_LIST(struct nmsg_io_buf)	w_nmsg;
	ISC_LIST(struct nmsg_io_pres)	r_pres;
	ISC_LIST(struct nmsg_io_pres)	w_pres;
	ProtobufCAllocator		ca;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	nmsg_io_output_mode		output_mode;
	nmsg_pbmodset			ms;
	pthread_mutex_t			lock;
	uint64_t			count;
	unsigned			rate, freq;
	size_t				interval;
};

struct nmsg_io_thr {
	ISC_LINK(struct nmsg_io_thr)	link;
	pthread_t			thr;
	union {
		struct nmsg_io_buf	*iobuf;
		struct nmsg_io_pres	*iopres;
	};
	nmsg_io				io;
	nmsg_rate			rate;
	uint64_t			count_input;
	uint64_t			count_output;
	uint64_t			count_payload;
};

/* Forward. */

static nmsg_res thr_nmsg_write(struct nmsg_io_thr *, struct nmsg_io_buf *,
			       Nmsg__Nmsg *);
static void *alloc_nmsg_payload(void *, size_t);
static void *thr_nmsg(void *);
static void *thr_pres(void *);
static void free_nmsg_payload(void *, void *);

/* Export. */

nmsg_io
nmsg_io_init(nmsg_pbmodset ms) {
	struct nmsg_io *io;

	io = calloc(1, sizeof(*io));
	if (io == NULL)
		return (NULL);
	io->ca.alloc = &alloc_nmsg_payload;
	io->ca.free = &free_nmsg_payload;
	io->ms = ms;
	io->output_mode = nmsg_io_output_mode_stripe;
	pthread_mutex_init(&io->lock, NULL);

	return (io);
}

nmsg_res
nmsg_io_loop(nmsg_io io) {
	ISC_LIST(struct nmsg_io_thr) iothreads;
	int res;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;
	struct nmsg_io_thr *iothr, *iothr_next;

	if (io->rate > 0 && io->freq == 0)
		io->freq = 100;

	ISC_LIST_INIT(iothreads);

	for (iobuf = ISC_LIST_HEAD(io->r_nmsg);
	     iobuf != NULL;
	     iobuf = ISC_LIST_NEXT(iobuf, link))
	{
		iothr = calloc(1, sizeof(*iothr));
		assert(iothr != NULL);
		iothr->io = io;
		iothr->iobuf = iobuf;
		ISC_LINK_INIT(iothr, link);
		ISC_LIST_APPEND(iothreads, iothr, link);
		assert(pthread_create(&iothr->thr, NULL, thr_nmsg, iothr) == 0);
	}

	for (iopres = ISC_LIST_HEAD(io->r_pres);
	     iopres != NULL;
	     iopres = ISC_LIST_NEXT(iopres, link))
	{
		iothr = calloc(1, sizeof(*iothr));
		assert(iothr != NULL);
		iothr->io = io;
		iothr->iobuf = iobuf;
		ISC_LINK_INIT(iothr, link);
		ISC_LIST_APPEND(iothreads, iothr, link);
		assert(pthread_create(&iothr->thr, NULL, thr_pres, iothr) != 0);
	}

	iothr = ISC_LIST_HEAD(iothreads);
	while (iothr != NULL) {
		iothr_next = ISC_LIST_NEXT(iothr, link);
		assert(pthread_join(iothr->thr, NULL) == 0);
		if (io->debug >= 5)
			fprintf(stderr, "nmsg_io: joined thread %d at %p\n",
				(int)iothr->thr, iothr);
		io->count += iothr->count_payload;
		free(iothr);
		iothr = iothr_next;
	}

	if (io->debug >= 1)
		fprintf(stderr, "nmsg_io: processed %" PRIu64 " payloads\n",
			io->count);

	return (nmsg_res_success);
}

void
nmsg_io_breakloop(nmsg_io io) {
	/* XXX */
}

void
nmsg_io_destroy(nmsg_io *io) {
	struct nmsg_io_buf *iobuf, *iobuf_next;
	struct nmsg_io_pres *iopres, *iopres_next;

	iobuf = ISC_LIST_HEAD((*io)->r_nmsg);
	while (iobuf != NULL) {
		iobuf_next = ISC_LIST_NEXT(iobuf, link);
		nmsg_buf_destroy(&iobuf->buf);
		if ((*io)->closed_fp != NULL)
			(*io)->closed_fp(*io, nmsg_io_fd_type_input,
					 iobuf->user);
		free(iobuf);
		iobuf = iobuf_next;
	}

	iobuf = ISC_LIST_HEAD((*io)->w_nmsg);
	while (iobuf != NULL) {
		iobuf_next = ISC_LIST_NEXT(iobuf, link);
		if ((*io)->closed_fp != NULL)
			(*io)->closed_fp(*io, nmsg_io_fd_type_output,
					 iobuf->user);
		nmsg_output_close(&iobuf->buf);
		free(iobuf);
		iobuf = iobuf_next;
	}

	iopres = ISC_LIST_HEAD((*io)->r_pres);
	while (iopres != NULL) {
		iopres_next = ISC_LIST_NEXT(iopres, link);
		if ((*io)->closed_fp != NULL)
			(*io)->closed_fp(*io, nmsg_io_fd_type_input_pres,
					 iobuf->user);
		fclose(iopres->fp);
		close(iopres->pres->fd);
		free(iopres);
		iopres = iopres_next;
	}

	iopres = ISC_LIST_HEAD((*io)->w_pres);
	while (iopres != NULL) {
		iopres_next = ISC_LIST_NEXT(iopres, link);
		if ((*io)->closed_fp != NULL)
			(*io)->closed_fp(*io, nmsg_io_fd_type_output_pres,
					 iobuf->user);
		fclose(iopres->fp);
		close(iopres->pres->fd);
		free(iopres);
		iopres = iopres_next;
	}

	free(*io);
	*io = NULL;
}

nmsg_res
nmsg_io_add_buf(nmsg_io io, nmsg_buf buf, void *user) {
	struct nmsg_io_buf *iobuf;

	iobuf = calloc(1, sizeof(*iobuf));
	if (iobuf == NULL)
		return (nmsg_res_memfail);

	iobuf->buf = buf;
	iobuf->user = user;
	pthread_mutex_init(&iobuf->lock, NULL);

	pthread_mutex_lock(&io->lock);
	if (buf->type == nmsg_buf_type_read)
		ISC_LIST_APPEND(io->r_nmsg, iobuf, link);
	else if (buf->type == nmsg_buf_type_write_sock ||
		 buf->type == nmsg_buf_type_write_file) {
		nmsg_output_set_allocator(buf, &io->ca);
		ISC_LIST_APPEND(io->w_nmsg, iobuf, link);
	}
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_pres(nmsg_io io, nmsg_pres pres, nmsg_pbmod mod, void *user) {
	struct nmsg_io_pres *iopres;

	iopres = calloc(1, sizeof(*iopres));
	if (iopres == NULL)
		return (nmsg_res_memfail);
	iopres->mod = mod;
	iopres->pres = pres;
	iopres->user = user;
	pthread_mutex_init(&iopres->lock, NULL);

	if (pres->type == nmsg_pres_type_read)
		iopres->fp = fdopen(pres->fd, "r");
	else if (pres->type == nmsg_pres_type_write)
		iopres->fp = fdopen(pres->fd, "w");
	if (iopres->fp == NULL) {
		free(iopres);
		return (nmsg_res_failure);
	}
	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->r_pres, iopres, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

void
nmsg_io_set_closed_fp(nmsg_io io, nmsg_io_closed_fp closed_fp) {
	io->closed_fp = closed_fp;
}

void
nmsg_io_set_count(nmsg_io io, size_t count) {
	io->count = count;
}

void
nmsg_io_set_debug(nmsg_io io, int debug) {
	io->debug = debug;
}

void
nmsg_io_set_interval(nmsg_io io, size_t interval) {
	io->interval = interval;
}

void
nmsg_io_set_output_mode(nmsg_io io, nmsg_io_output_mode output_mode) {
	switch (output_mode) {
		case nmsg_io_output_mode_stripe:
		case nmsg_io_output_mode_mirror:
			io->output_mode = output_mode;
	}
}

void
nmsg_io_set_rate(nmsg_io io, unsigned rate) {
	io->rate = rate;
}

void
nmsg_io_set_freq(nmsg_io io, unsigned freq) {
	io->freq = freq;
}

/* Private. */

static void *
thr_nmsg(void *user) {
	Nmsg__Nmsg *nmsg;
	Nmsg__NmsgPayload *np;
	ProtobufCAllocator ca;
	char *thrname;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_thr *iothr;
	unsigned n;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	if (io->rate > 0)
		iothr->rate = nmsg_rate_init(io->rate, io->freq);

	if (io->debug >= 4)
		fprintf(stderr, "nmsg_io: started nmsg thread @ %p\n", iothr);

	if (io->output_mode == nmsg_io_output_mode_stripe) {
		iobuf = ISC_LIST_HEAD(io->w_nmsg);
		for (;;) {
			res = nmsg_input_next(iothr->iobuf->buf, &nmsg);
			iothr->count_input += 1;
			if (res == nmsg_res_success) {
				if (thr_nmsg_write(iothr, iobuf, nmsg)
				    != nmsg_res_success)
					goto thr_nmsg_out;
				nmsg__nmsg__free_unpacked(nmsg, NULL);
				iobuf = ISC_LIST_NEXT(iobuf, link);
				if (iobuf == NULL)
					iobuf = ISC_LIST_HEAD(io->w_nmsg);
			} else {
				goto thr_nmsg_out;
			}
		}
	} else if (io->output_mode == nmsg_io_output_mode_mirror) {
		for (;;) {
			res = nmsg_input_next(iothr->iobuf->buf, &nmsg);
			iothr->count_input += 1;
			if (res == nmsg_res_success) {
				for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
				     iobuf != NULL;
				     iobuf = ISC_LIST_NEXT(iobuf, link))
				{
					if (thr_nmsg_write(iothr, iobuf, nmsg)
					    != nmsg_res_success)
						goto thr_nmsg_out;
				}
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			} else {
				goto thr_nmsg_out;
			}
		}
	}
thr_nmsg_out:
	if (io->debug >= 4)
		fprintf(stderr, "nmsg_io: iothr=%p count_input=%zd "
			"count_output=%zd count_payload=%zd\n",
			iothr, iothr->count_input, iothr->count_output,
			iothr->count_payload);

	return (NULL);
}

static nmsg_res
thr_nmsg_write(struct nmsg_io_thr *iothr, struct nmsg_io_buf *iobuf,
	       Nmsg__Nmsg *nmsg)
{
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	unsigned n;

	pthread_mutex_lock(&iobuf->lock);
	for (n = 0; n < nmsg->n_payloads; n++) {
		iothr->count_payload += 1;
		np = nmsg_payload_dup(nmsg->payloads[n], &iothr->io->ca);
		res = nmsg_output_append(iobuf->buf, np);
		if (!(res == nmsg_res_success ||
		      res == nmsg_res_pbuf_written))
			return (nmsg_res_failure);
		if (res == nmsg_res_pbuf_written) {
			iothr->count_output += 1;
			if (iothr->io->rate > 0)
				nmsg_rate_sleep(iothr->rate);
		}
	}
	pthread_mutex_unlock(&iobuf->lock);
	return (nmsg_res_success);
}

static void *
thr_pres(void *user) {
	struct nmsg_io_thr *iothr = (struct nmsg_io_thr *) user;

	if (iothr->io->debug >= 4)
		fprintf(stderr, "nmsg_io: started pres thread @ %p\n", iothr);
	return (NULL);
}

static void *
alloc_nmsg_payload(void *user, size_t sz) {
	return (malloc(sz));
}

static void
free_nmsg_payload(void *user, void *ptr) {
	Nmsg__NmsgPayload *np = (Nmsg__NmsgPayload *) ptr;
	if (np->has_payload)
		free(np->payload.data);
	free(ptr);
}
