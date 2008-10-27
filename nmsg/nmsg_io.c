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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <pthread.h>
#include <unistd.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "nmsg.h"
#include "nmsg_private.h"

/* Data structures. */

struct nmsg_io_pres {
	ISC_LINK(struct nmsg_io_pres)	link;
	FILE *				fp;
	int				fd;
	nmsg_pbmod			mod;
	pthread_mutex_t			lock;
	void *				user;
};

struct nmsg_io_buf {
	ISC_LINK(struct nmsg_io_buf)	link;
	nmsg_buf			buf;
	pthread_mutex_t			lock;
	void *				user;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_buf)	r_nmsg;
	ISC_LIST(struct nmsg_io_buf)	w_nmsg;
	ISC_LIST(struct nmsg_io_pres)	r_pres;
	ISC_LIST(struct nmsg_io_pres)	w_pres;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	nmsg_io_output_mode		output_mode;
	nmsg_pbmodset			ms;
	pthread_mutex_t			lock;
	size_t				count;
	size_t				interval;
};

/* Forward. */

static void *thr_nmsg(void *);
static void *thr_pres(void *);

/* Export. */

nmsg_io
nmsg_io_init(nmsg_pbmodset ms) {
	struct nmsg_io *io;

	io = calloc(1, sizeof(*io));
	if (io == NULL)
		return (NULL);
	io->ms = ms;
	io->output_mode = nmsg_io_output_mode_stripe;
	pthread_mutex_init(&io->lock, NULL);

	return (io);
}

nmsg_res
nmsg_io_loop(nmsg_io io) {
	pthread_t thr;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;

	for (iobuf = ISC_LIST_HEAD(io->r_nmsg);
	     iobuf != NULL;
	     iobuf = ISC_LIST_NEXT(iobuf, link))
	{
		if (pthread_create(&thr, NULL, thr_nmsg, iobuf) != 0)
			return (nmsg_res_failure);
	}

	for (iopres = ISC_LIST_HEAD(io->r_pres);
	     iopres != NULL;
	     iopres = ISC_LIST_NEXT(iopres, link))
	{
		if (pthread_create(&thr, NULL, thr_pres, iopres) != 0)
			return (nmsg_res_failure);
	}

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
		close(iopres->fd);
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
		close(iopres->fd);
		free(iopres);
		iopres = iopres_next;
	}

	free(*io);
	*io = NULL;
}

nmsg_res
nmsg_io_add_buf(nmsg_io io, nmsg_buf buf, void *user) {
	struct nmsg_io_buf *iobuf;

	if (io->debug >= 4)
		fprintf(stderr, "%s: io=%p buf=%p user=%p\n", __func__, io, buf, user);

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
		 buf->type == nmsg_buf_type_write_file)
		ISC_LIST_APPEND(io->w_nmsg, iobuf, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_pres_input(nmsg_io io, nmsg_pbmod mod, int fd, void *user) {
	struct nmsg_io_pres *iopres;

	if (io->debug >= 4)
		fprintf(stderr, "%s: io=%p mod=%p fd=%d user=%p\n", __func__, io, mod, fd, user);

	iopres = calloc(1, sizeof(*iopres));
	if (iopres == NULL)
		return (nmsg_res_memfail);

	iopres->fd = fd;
	iopres->mod = mod;
	iopres->user = user;
	pthread_mutex_init(&iopres->lock, NULL);

	iopres->fp = fdopen(fd, "r");
	if (iopres->fp == NULL) {
		free(iopres);
		return (nmsg_res_failure);
	}

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->r_pres, iopres, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_pres_output(nmsg_io io, nmsg_pbmod mod, int fd, void *user) {
	struct nmsg_io_pres *iopres;

	if (io->debug >= 4)
		fprintf(stderr, "%s: io=%p mod=%p fd=%d user=%p\n", __func__, io, mod, fd, user);

	iopres = calloc(1, sizeof(*iopres));
	if (iopres == NULL)
		return (nmsg_res_memfail);

	iopres->fd = fd;
	iopres->mod = mod;
	iopres->user = user;
	pthread_mutex_init(&iopres->lock, NULL);

	iopres->fp = fdopen(fd, "w");
	if (iopres->fp == NULL) {
		free(iopres);
		return (nmsg_res_failure);
	}

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->w_pres, iopres, link);
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

void nmsg_io_set_output_mode(nmsg_io io, nmsg_io_output_mode output_mode) {
	switch (output_mode) {
		case nmsg_io_output_mode_stripe:
		case nmsg_io_output_mode_mirror:
			io->output_mode = output_mode;
	}
}

/* Private. */

static void *
thr_nmsg(void *user) {
	return (NULL);
}

static void *
thr_pres(void *user) {
	return (NULL);
}
