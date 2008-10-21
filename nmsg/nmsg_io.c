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

struct nmsg_io_fdfile {
	ISC_LINK(struct nmsg_io_fdfile)	link;
	int				fd;
	FILE *				fp;
	void *				user;
};

struct nmsg_io_fdbuf {
	ISC_LINK(struct nmsg_io_fdbuf)	link;
	int				fd;
	nmsg_buf			buf;
	void *				user;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_fdbuf)	r_nmsg;
	ISC_LIST(struct nmsg_io_fdbuf)	w_nmsg;
	ISC_LIST(struct nmsg_io_fdfile)	r_pres;
	ISC_LIST(struct nmsg_io_fdfile)	w_pres;
	nmsg_io_output_mode		output_mode;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	pthread_mutex_t			lock;
	size_t				count;
	size_t				interval;
	size_t				wbufsz;
};

/* Export. */

nmsg_io
nmsg_io_init(void) {
	struct nmsg_io *io;

	io = calloc(1, sizeof(*io));
	if (io == NULL)
		return (NULL);
	io->output_mode = nmsg_io_output_mode_stripe;
	io->wbufsz = nmsg_wbufsize_max;
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
	/* XXX */
	free(*io);
	*io = NULL;
}

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

#if 0
nmsg_res
nmsg_io_add_fd_input(nmsg_io, int fd, void *user) {
	struct nmsg_io_fdbuf *fdbuf;

	fdbuf = calloc(1, sizeof(*fdbuf));
	if (fdbuf == NULL)
		return (nmsg_res_memfail);
	fdbuf->fd = fd;
	fdbuf->buf = nmsg_input_open(fd);
	fdbuf->user = user;

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->r_nmsg, fdbuf, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_fd_output(nmsg_io, int fd, void *user) {
	struct nmsg_io_fdbuf *fdbuf;

	fdbuf = calloc(1, sizeof(*fdbuf));
	if (fdbuf == NULL)
		return (nmsg_res_memfail);
	fdbuf->fd = fd;
	fdbuf->buf = nmsg_output_open(fd, io->wbufsz);
	fdbuf->user = user;

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->w_nmsg, fdbuf, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_fd_input_pres(nmsg_io, int fd, void *user) {
	struct nmsg_io_fdfile *fdfile;

	fdfile = calloc(1, sizeof(*fdfile));
	if (fdfile == NULL)
		return (nmsg_res_memfail);
	fdfile->fd = fd;
	fdfile->fp = fdopen(fd, "r");
	fdfile->user = user;

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->r_pres, fdfile, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_fd_output_pres(nmsg_io, int fd, void *user) {
	struct nmsg_io_fdfile *fdfile;

	fdfile = calloc(1, sizeof(*fdfile));
	if (fdfile == NULL)
		return (nmsg_res_memfail);
	fdfile->fd = fd;
	fdfile->fp = fdopen(fd, "w");
	fdfile->user = user;

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->w_pres, fdfile, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
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

void nmsg_io_set_wbufsz(nmsg_io io, size_t wbufsz) {
	if (wbufsz < nmsg_wbufsize_min)
		wbufsz = nmsg_wbufsize_min;
	if (wbufsz > nmsg_wbufsize_max)
		wbufsz = nmsg_wbufsize_max;
	io->wbufsz = wbufsz;
}
