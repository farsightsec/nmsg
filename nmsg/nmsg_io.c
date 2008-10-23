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

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "nmsg.h"
#include "nmsg_private.h"

/* Data structures. */

struct nmsg_io_pres {
	ISC_LINK(struct nmsg_io_pres)	link;
	int				fd;
	nmsg_pbmod			mod;
	FILE *				fp;
	void *				user;
};

struct nmsg_io_buf {
	ISC_LINK(struct nmsg_io_buf)	link;
	nmsg_buf			buf;
	void *				user;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_buf)	r_nmsg;
	ISC_LIST(struct nmsg_io_buf)	w_nmsg;
	ISC_LIST(struct nmsg_io_pres)	r_pres;
	ISC_LIST(struct nmsg_io_pres)	w_pres;
	nmsg_io_output_mode		output_mode;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	nmsg_pbmodset			ms;
	pthread_mutex_t			lock;
	size_t				count;
	size_t				interval;
};

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
	/* XXX */
	return (nmsg_res_success);
}

void
nmsg_io_breakloop(nmsg_io io) {
	/* XXX */
}

void
nmsg_io_destroy(nmsg_io *io) {
	struct nmsg_io_pres *iopres, *iopres_next;
	struct nmsg_io_buf *iobuf, *iobuf_next;

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
		nmsg_output_close(&iobuf->buf);
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

	pthread_mutex_lock(&io->lock);
	if (buf->type == nmsg_buf_type_read)
		ISC_LIST_APPEND(io->r_nmsg, iobuf, link);
	else if (buf->type == nmsg_buf_type_write)
		ISC_LIST_APPEND(io->w_nmsg, iobuf, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_pres_input(nmsg_io io, nmsg_pbmod mod, int fd, void *user) {
	struct nmsg_io_pres *pres;

	pres = calloc(1, sizeof(*pres));
	if (pres == NULL)
		return (nmsg_res_memfail);

	pres->fd = fd;
	pres->mod = mod;
	pres->user = user;

	pres->fp = fdopen(fd, "r");
	if (pres->fp == NULL) {
		free(pres);
		return (nmsg_res_failure);
	}

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->r_pres, pres, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_pres_output(nmsg_io io, nmsg_pbmod mod, int fd, void *user) {
	struct nmsg_io_pres *pres;

	pres = calloc(1, sizeof(*pres));
	if (pres == NULL)
		return (nmsg_res_memfail);

	pres->fd = fd;
	pres->mod = mod;
	pres->user = user;

	pres->fp = fdopen(fd, "w");
	if (pres->fp == NULL) {
		free(pres);
		return (nmsg_res_failure);
	}

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->w_pres, pres, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

#if 0
nmsg_res
nmsg_io_add_fd(nmsg_io io, nmsg_io_fd_type fd_type, int fd, void *user) {
	if (fd_type == nmsg_io_fd_type_input ||
	    fd_type == nmsg_io_fd_type_output)
	{
		struct nmsg_io_fdbuf *fdbuf;
		fdbuf = calloc(1, sizeof(*fdbuf));
		if (fdbuf == NULL)
			return (nmsg_res_memfail);
		fdbuf->fd = fd;
		fdbuf->user = user;

		pthread_mutex_lock(&io->lock);
		if (fd_type == nmsg_io_fd_type_input) {
			fdbuf->buf = nmsg_input_open(fd);
			ISC_LIST_APPEND(io->r_nmsg, fdbuf, link);
		} else {
			fdbuf->buf = nmsg_output_open(fd, io->wbufsz);
			ISC_LIST_APPEND(io->w_nmsg, fdbuf, link);
		}
		pthread_mutex_unlock(&io->lock);

		return (nmsg_res_success);
	}

	if (fd_type == nmsg_io_fd_type_input_pres ||
	    fd_type == nmsg_io_fd_type_output_pres)
	{
		struct nmsg_io_fdfile *fdfile;
		fdfile = calloc(1, sizeof(*fdfile));
		if (fdfile == NULL)
			return (nmsg_res_memfail);
		fdfile->fd = fd;
		fdfile->user = user;

		pthread_mutex_lock(&io->lock);
		if (fd_type == nmsg_io_fd_type_input_pres) {
			fdfile->fp = fdopen(fd, "r");
			if (fdfile->fp == NULL) {
				pthread_mutex_unlock(&io->lock);
				return (nmsg_res_failure);
			}
			ISC_LIST_APPEND(io->r_pres, fdfile, link);
		} else {
			fdfile->fp = fdopen(fd, "w");
			if (fdfile->fp == NULL) {
				pthread_mutex_unlock(&io->lock);
				return (nmsg_res_failure);
			}
			ISC_LIST_APPEND(io->w_pres, fdfile, link);
		}
		pthread_mutex_unlock(&io->lock);

		return (nmsg_res_success);
	}

	return (nmsg_res_failure);
}
#endif

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
