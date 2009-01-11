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

#include "nmsg_port.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "private.h"
#include "input.h"
#include "io.h"
#include "output.h"
#include "payload.h"
#include "pbmod.h"
#include "pbmodset.h"
#include "time.h"

/* Data structures. */

struct nmsg_io_pres {
	ISC_LINK(struct nmsg_io_pres)	link;
	FILE				*fp;
	nmsg_pbmod			mod;
	nmsg_pres			pres;
	pthread_mutex_t			lock;
	struct timespec			last;
	void				*clos, *user;
	uint64_t			count_pres_out, count_pres_payload_out;
};

struct nmsg_io_buf {
	ISC_LINK(struct nmsg_io_buf)	link;
	nmsg_buf			buf;
	pthread_mutex_t			lock;
	struct timespec			last;
	void				*user;
	uint64_t			count_nmsg_out, count_nmsg_payload_out;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_buf)	r_nmsg;
	ISC_LIST(struct nmsg_io_buf)	w_nmsg;
	ISC_LIST(struct nmsg_io_pres)	r_pres;
	ISC_LIST(struct nmsg_io_pres)	w_pres;
	ISC_LIST(struct nmsg_io_thr)	iothreads;
	bool				quiet, zlibout;
	char				*endline;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	nmsg_io_output_mode		output_mode;
	nmsg_pbmodset			ms;
	pthread_mutex_t			lock;
	size_t				max;
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
	};
	uint64_t			count_nmsg_in, count_nmsg_payload_in;
	uint64_t			count_pres_in, count_pres_payload_in;
};

/* Forward. */

static Nmsg__NmsgPayload *make_nmsg_payload(struct nmsg_io_thr *, uint8_t *,
					    size_t);
static nmsg_res write_nmsg(struct nmsg_io_thr *, struct nmsg_io_buf *,
			   Nmsg__Nmsg *);
static nmsg_res write_nmsg_dup(struct nmsg_io_thr *, struct nmsg_io_buf *,
			       const Nmsg__Nmsg *);
static nmsg_res write_nmsg_payload(struct nmsg_io_thr *, struct nmsg_io_buf *,
				   Nmsg__NmsgPayload *);
static nmsg_res write_pres(struct nmsg_io_thr *, struct nmsg_io_pres *,
			   const Nmsg__Nmsg *);
static void *thr_nmsg(void *);
static void *thr_pres(void *);
static void init_timespec_intervals(nmsg_io);

/* Export. */

nmsg_io
nmsg_io_init(nmsg_pbmodset ms, size_t max) {
	struct nmsg_io *io;

	io = calloc(1, sizeof(*io));
	if (io == NULL)
		return (NULL);
	io->ms = ms;
	io->output_mode = nmsg_io_output_mode_stripe;
	pthread_mutex_init(&io->lock, NULL);
	ISC_LIST_INIT(io->iothreads);

	if (max == 0)
		io->max = NMSG_WBUFSZ_ETHER;
	else if (max < NMSG_WBUFSZ_MIN)
		io->max = NMSG_WBUFSZ_MIN;
	else if (max > NMSG_WBUFSZ_MAX)
		io->max = NMSG_WBUFSZ_MAX;
	else
		io->max = max;

	/* reserve space for the outer nmsg layer */
	io->max -= (NMSG_HDRSZ + NMSG_LENHDRSZ_V2 + NMSG_PAYHDRSZ);

	return (io);
}

void
nmsg_io_breakloop(nmsg_io io) {
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

	io->stop = true;
	nmsg_time_sleep(&ts);
	if (io->stopped != true) {
		struct nmsg_io_thr *iothr;

		for (iothr = ISC_LIST_HEAD(io->iothreads);
		     iothr != NULL;
		     iothr = ISC_LIST_NEXT(iothr, link))
		{
			pthread_cancel(iothr->thr);
		}
	}
}

nmsg_res
nmsg_io_loop(nmsg_io io) {
	nmsg_res res;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;
	struct nmsg_io_thr *iothr, *iothr_next;

	res = nmsg_res_success;

	if (io->interval > 0)
		init_timespec_intervals(io);

	if (io->endline == NULL)
		io->endline = strdup("\n");

	for (iobuf = ISC_LIST_HEAD(io->r_nmsg);
	     iobuf != NULL;
	     iobuf = ISC_LIST_NEXT(iobuf, link))
	{
		iothr = calloc(1, sizeof(*iothr));
		assert(iothr != NULL);
		iothr->io = io;
		iothr->iobuf = iobuf;
		ISC_LINK_INIT(iothr, link);
		ISC_LIST_APPEND(io->iothreads, iothr, link);
		assert(pthread_create(&iothr->thr, NULL, thr_nmsg, iothr) == 0);
	}

	for (iopres = ISC_LIST_HEAD(io->r_pres);
	     iopres != NULL;
	     iopres = ISC_LIST_NEXT(iopres, link))
	{
		iothr = calloc(1, sizeof(*iothr));
		assert(iothr != NULL);
		iothr->io = io;
		iothr->iopres = iopres;
		ISC_LINK_INIT(iothr, link);
		ISC_LIST_APPEND(io->iothreads, iothr, link);
		assert(pthread_create(&iothr->thr, NULL, thr_pres, iothr) == 0);
	}

	iothr = ISC_LIST_HEAD(io->iothreads);
	while (iothr != NULL) {
		iothr_next = ISC_LIST_NEXT(iothr, link);
		assert(pthread_join(iothr->thr, NULL) == 0);
		if (iothr->res != nmsg_res_success) {
			if (io->debug >= 3)
				fprintf(stderr, "nmsg_io: iothr=%p res=%d\n",
					iothr, iothr->res);
			res = nmsg_res_failure;
		}
		free(iothr);
		iothr = iothr_next;
	}

	io->stopped = true;

	return (res);
}

void
nmsg_io_destroy(nmsg_io *io) {
	nmsg_res res;
	struct nmsg_io_close_event ce;
	struct nmsg_io_buf *iobuf, *iobuf_next;
	struct nmsg_io_pres *iopres, *iopres_next;

	iobuf = ISC_LIST_HEAD((*io)->r_nmsg);
	while (iobuf != NULL) {
		iobuf_next = ISC_LIST_NEXT(iobuf, link);
		nmsg_buf_destroy(&iobuf->buf);
		if ((*io)->closed_fp != NULL) {
			ce.buf = NULL;
			ce.closetype = nmsg_io_close_type_eof;
			ce.fdtype = nmsg_io_fd_type_input_nmsg;
			ce.io = *io;
			ce.user = iobuf->user;
			(*io)->closed_fp(&ce);
		}
		free(iobuf);
		iobuf = iobuf_next;
	}

	iobuf = ISC_LIST_HEAD((*io)->w_nmsg);
	while (iobuf != NULL) {
		iobuf_next = ISC_LIST_NEXT(iobuf, link);
		if ((*io)->closed_fp != NULL) {
			ce.buf = NULL;
			ce.closetype = nmsg_io_close_type_eof;
			ce.fdtype = nmsg_io_fd_type_output_nmsg;
			ce.io = *io;
			ce.user = iobuf->user;
			(*io)->closed_fp(&ce);
		}
		res = nmsg_output_close(&iobuf->buf);
		if (res == nmsg_res_pbuf_written)
			iobuf->count_nmsg_out += 1;
		if ((*io)->debug >= 1)
			fprintf(stderr, "nmsg_io: iobuf=%p"
				" count_nmsg_out=%" PRIu64
				" count_nmsg_payload_out=%" PRIu64
				"\n",
				iobuf,
				iobuf->count_nmsg_out,
				iobuf->count_nmsg_payload_out);
		free(iobuf);
		iobuf = iobuf_next;
	}

	iopres = ISC_LIST_HEAD((*io)->r_pres);
	while (iopres != NULL) {
		iopres_next = ISC_LIST_NEXT(iopres, link);
		if ((*io)->closed_fp != NULL) {
			ce.pres = NULL;
			ce.closetype = nmsg_io_close_type_eof;
			ce.fdtype = nmsg_io_fd_type_input_pres;
			ce.io = *io;
			ce.user = iopres->user;
			(*io)->closed_fp(&ce);
		}
		fclose(iopres->fp);
		nmsg_output_close_pres(&iopres->pres);
		free(iopres);
		iopres = iopres_next;
	}

	iopres = ISC_LIST_HEAD((*io)->w_pres);
	while (iopres != NULL) {
		iopres_next = ISC_LIST_NEXT(iopres, link);
		if ((*io)->closed_fp != NULL) {
			ce.pres = NULL;
			ce.closetype = nmsg_io_close_type_eof;
			ce.fdtype = nmsg_io_fd_type_output_pres;
			ce.io = *io;
			ce.user = iopres->user;
			(*io)->closed_fp(&ce);
		}
		if ((*io)->debug >= 1)
			fprintf(stderr, "nmsg_io: iopres=%p"
				" count_pres_out=%" PRIu64
				" count_pres_payload_out=%" PRIu64
				"\n",
				iopres,
				iopres->count_pres_out,
				iopres->count_pres_payload_out);
		fclose(iopres->fp);
		nmsg_output_close_pres(&iopres->pres);
		free(iopres);
		iopres = iopres_next;
	}

	free((*io)->endline);
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
	if (buf->type == nmsg_buf_type_read_file ||
	    buf->type == nmsg_buf_type_read_sock)
		ISC_LIST_APPEND(io->r_nmsg, iobuf, link);
	else if (buf->type == nmsg_buf_type_write_sock ||
		 buf->type == nmsg_buf_type_write_file)
	{
		ISC_LIST_APPEND(io->w_nmsg, iobuf, link);
	}
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_pres(nmsg_io io, nmsg_pres pres, nmsg_pbmod mod, void *user) {
	struct nmsg_io_pres *iopres;

	if (pres->type == nmsg_pres_type_write)
		assert(mod == NULL);

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
	if (pres->flush == true) {
		if (setvbuf(iopres->fp, NULL, _IOLBF, 0) != 0)
			return (nmsg_res_failure);
	}

	pthread_mutex_lock(&io->lock);
	if (pres->type == nmsg_pres_type_read)
		ISC_LIST_APPEND(io->r_pres, iopres, link);
	if (pres->type == nmsg_pres_type_write)
		ISC_LIST_APPEND(io->w_pres, iopres, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

void
nmsg_io_set_closed_fp(nmsg_io io, nmsg_io_closed_fp closed_fp) {
	io->closed_fp = closed_fp;
}

void
nmsg_io_set_count(nmsg_io io, unsigned count) {
	io->count = count;
}

void
nmsg_io_set_debug(nmsg_io io, int debug) {
	io->debug = debug;
}

void
nmsg_io_set_endline(nmsg_io io, const char *endline) {
	if (io->endline != NULL)
		free(io->endline);
	io->endline = strdup(endline);
}

void
nmsg_io_set_interval(nmsg_io io, unsigned interval) {
	io->interval = interval;
}

void
nmsg_io_set_quiet(nmsg_io io, bool quiet) {
	io->quiet = quiet;
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
nmsg_io_set_user(nmsg_io io, unsigned pos, unsigned user) {
	if (pos == 0 || pos == 1)
		io->user[pos] = user;
	if (pos + 1 > io->n_user)
		io->n_user = pos + 1;
}

void
nmsg_io_set_zlibout(nmsg_io io, bool zlibout) {
	io->zlibout = zlibout;
}

/* Private. */

static void *
thr_nmsg(void *user) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;
	struct nmsg_io_thr *iothr;
	unsigned i;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	iobuf = ISC_LIST_HEAD(io->w_nmsg);
	iopres = ISC_LIST_HEAD(io->w_pres);
	nmsg = NULL;

	if (io->debug >= 4)
		fprintf(stderr, "nmsg_io: started nmsg thread @ %p\n", iothr);

	for (;;) {
		if (io->stop == true) {
			if (nmsg != NULL)
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			break;
		}
		res = nmsg_input_next(iothr->iobuf->buf, &nmsg);
		if (res != nmsg_res_success)
			break;

		iothr->count_nmsg_in += 1;
		iothr->count_nmsg_payload_in += nmsg->n_payloads;
		nmsg_time_get(&iothr->now);

		if (io->output_mode == nmsg_io_output_mode_stripe) {
			if (iopres != NULL) {
				if ((res = write_pres(iothr, iopres, nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
				iopres = ISC_LIST_NEXT(iopres, link);
				if (iopres == NULL)
					iopres = ISC_LIST_HEAD(io->w_pres);
			}
			if (iobuf != NULL) {
				if ((res = write_nmsg(iothr, iobuf, nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
				iobuf = ISC_LIST_NEXT(iobuf, link);
				if (iobuf == NULL)
					iobuf = ISC_LIST_HEAD(io->w_nmsg);

				nmsg->n_payloads = 0;
			}
		} else if (io->output_mode == nmsg_io_output_mode_mirror) {
			for (iopres = ISC_LIST_HEAD(io->w_pres);
			     iopres != NULL;
			     iopres = ISC_LIST_NEXT(iopres, link))
			{
				if ((res = write_pres(iothr, iopres, nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
			}
			for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
			     iobuf != NULL;
			     iobuf = ISC_LIST_NEXT(iobuf, link))
			{
				if ((res = write_nmsg_dup(iothr, iobuf, nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
			}
		}
		nmsg__nmsg__free_unpacked(nmsg, NULL);
		nmsg = NULL;
	}
thr_nmsg_end:
	if (nmsg != NULL) {
		if (iothr->res == nmsg_res_stop) {
			for (i = 0; i < nmsg->n_payloads; i++)
				if (nmsg->payloads[i] != NULL) {
					if (nmsg->payloads[i]->has_payload)
						free(nmsg->payloads[i]->payload.data);
					free(nmsg->payloads[i]);
				}
		}
		for (i = 0; i < nmsg->n_payloads; i++)
			nmsg->payloads[i] = NULL;
		nmsg->n_payloads = 0;
		nmsg__nmsg__free_unpacked(nmsg, NULL);
	}
	if (io->debug >= 2)
		fprintf(stderr, "nmsg_io: iothr=%p"
			" count_nmsg_in=%" PRIu64
			" count_nmsg_payload_in=%" PRIu64
			"\n",
			iothr,
			iothr->count_nmsg_in,
			iothr->count_nmsg_payload_in);
	return (NULL);
}

static nmsg_res
write_nmsg(struct nmsg_io_thr *iothr, struct nmsg_io_buf *iobuf,
	   Nmsg__Nmsg *nmsg)
{
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	unsigned n;

	pthread_mutex_lock(&iobuf->lock);
	for (n = 0; n < nmsg->n_payloads; n++) {
		np = nmsg->payloads[n];
		res = write_nmsg_payload(iothr, iobuf, np);
		nmsg->payloads[n] = NULL;
		if (res != nmsg_res_success) {
			pthread_mutex_unlock(&iobuf->lock);
			return (res);
		}
	}
	pthread_mutex_unlock(&iobuf->lock);
	return (nmsg_res_success);
}

static nmsg_res
write_nmsg_dup(struct nmsg_io_thr *iothr, struct nmsg_io_buf *iobuf,
	       const Nmsg__Nmsg *nmsg)
{
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	unsigned n;

	pthread_mutex_lock(&iobuf->lock);
	for (n = 0; n < nmsg->n_payloads; n++) {
		np = nmsg_payload_dup(nmsg->payloads[n]);
		res = write_nmsg_payload(iothr, iobuf, np);
		if (res != nmsg_res_success) {
			pthread_mutex_unlock(&iobuf->lock);
			return (res);
		}
	}
	pthread_mutex_unlock(&iobuf->lock);
	return (nmsg_res_success);
}

static nmsg_res
write_nmsg_payload(struct nmsg_io_thr *iothr, struct nmsg_io_buf *iobuf,
		   Nmsg__NmsgPayload *np)
{
	nmsg_io io;
	nmsg_res res;
	struct nmsg_io_close_event ce;

	io = iothr->io;

	if (io->n_user > 0) {
		np->n_user = io->n_user;
		np->user = io->user;
	}
	res = nmsg_output_append(iobuf->buf, np);
	if (!(res == nmsg_res_success ||
	      res == nmsg_res_pbuf_written))
		return (nmsg_res_failure);
	if (res == nmsg_res_pbuf_written)
		iobuf->count_nmsg_out += 1;
	iobuf->count_nmsg_payload_out += 1;

	res = nmsg_res_success;

	if (io->count > 0 && iobuf->count_nmsg_payload_out % io->count == 0) {
		if (iobuf->user != NULL) {
			ce.buf = &iobuf->buf;
			ce.closetype = nmsg_io_close_type_count;
			ce.fdtype = nmsg_io_fd_type_output_nmsg;
			ce.io = io;
			ce.user = iobuf->user;
			nmsg_output_close(&iobuf->buf);
			io->closed_fp(&ce);
		} else {
			res = nmsg_res_stop;
		}
	}

	if (io->interval > 0 &&
	    ((unsigned) iothr->now.tv_sec - iobuf->last.tv_sec) >= io->interval)
	{
		if (iobuf->user != NULL) {
			memcpy(&iobuf->last, &iothr->now, sizeof(iothr->now));
			ce.buf = &iobuf->buf;
			ce.closetype = nmsg_io_close_type_interval;
			ce.fdtype = nmsg_io_fd_type_output_nmsg;
			ce.io = io;
			ce.user = iobuf->user;
			nmsg_output_close(&iobuf->buf);
			io->closed_fp(&ce);
		} else {
			res = nmsg_res_stop;
		}
	}
	return (res);
}

static void *
thr_pres(void *user) {
	Nmsg__NmsgPayload *np;
	char line[1024];
	struct nmsg_io *io;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;
	struct nmsg_io_thr *iothr;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	iobuf = ISC_LIST_HEAD(io->w_nmsg);
	iopres = iothr->iopres;
	np = NULL;

	iopres->clos = nmsg_pbmod_init(iopres->mod, io->max, io->debug);

	if (iothr->io->debug >= 4)
		fprintf(stderr, "nmsg_io: started pres thread @ %p\n", iothr);

	if (iobuf == NULL) {
		fprintf(stderr, "nmsg_io: no nmsg outputs\n");
		goto thr_pres_end;
	}

	while (fgets(line, sizeof(line), iopres->fp) != NULL) {
		nmsg_res res;
		size_t sz;
		uint8_t *pbuf;

		if (io->stop == true)
			goto thr_pres_end;

		iothr->count_pres_in += 1;
		res = nmsg_pbmod_pres2pbuf(iopres->mod, iopres->clos, line,
					   &pbuf, &sz);
		if (res == nmsg_res_failure) {
			iothr->res = res;
			goto thr_pres_end;
		}
		if (res == nmsg_res_success)
			continue;

		/* nmsg_res_pbuf_ready */

		nmsg_time_get(&iothr->now);
		iothr->count_pres_payload_in += 1;
		np = make_nmsg_payload(iothr, pbuf, sz);
		if (np == NULL) {
			free(pbuf);
			iothr->res = nmsg_res_memfail;
			goto thr_pres_end;
		}

		if (io->output_mode == nmsg_io_output_mode_stripe) {
			pthread_mutex_lock(&iobuf->lock);
			res = write_nmsg_payload(iothr, iobuf, np);
			pthread_mutex_unlock(&iobuf->lock);
			if (res != nmsg_res_success) {
				iothr->res = res;
				goto thr_pres_end;
			}

			iobuf = ISC_LIST_NEXT(iobuf, link);
			if (iobuf == NULL)
				iobuf = ISC_LIST_HEAD(io->w_nmsg);
		} else if (io->output_mode == nmsg_io_output_mode_mirror) {
			for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
			     iobuf != NULL;
			     iobuf = ISC_LIST_NEXT(iobuf, link))
			{
				Nmsg__NmsgPayload *npdup;

				npdup = nmsg_payload_dup(np);
				if (npdup == NULL) {
					iothr->res = nmsg_res_memfail;
					goto thr_pres_end;
				}

				pthread_mutex_lock(&iobuf->lock);
				res = write_nmsg_payload(iothr, iobuf, npdup);
				pthread_mutex_unlock(&iobuf->lock);
				if (res != nmsg_res_success) {
					iothr->res = res;
					goto thr_pres_end;
				}
			}
			nmsg_payload_free(&np);
		}
	}
thr_pres_end:
	nmsg_pbmod_fini(iopres->mod, iopres->clos);
	if (io->debug >= 2)
		fprintf(stderr, "nmsg_io: iothr=%p"
			" count_pres_in=%" PRIu64
			" count_pres_payload_in=%" PRIu64
			"\n",
			iothr,
			iothr->count_pres_in,
			iothr->count_pres_payload_in);
	return (NULL);
}

static nmsg_res
write_pres(struct nmsg_io_thr *iothr, struct nmsg_io_pres *iopres,
	   const Nmsg__Nmsg *nmsg)
{
	Nmsg__NmsgPayload *np;
	char *pres;
	char when[32];
	nmsg_pbmod mod;
	nmsg_res res;
	struct nmsg_io_close_event ce;
	struct nmsg_io *io;
	struct tm *tm;
	time_t t;
	unsigned n;

	io = iothr->io;
	res = nmsg_res_success;
	pthread_mutex_lock(&iopres->lock);
	for (n = 0; n < nmsg->n_payloads; n++) {
		np = nmsg->payloads[n];
		t = np->time_sec;
		tm = gmtime(&t);
		strftime(when, sizeof(when), "%Y-%m-%d %T", tm);
		mod = nmsg_pbmodset_lookup(io->ms, np->vid, np->msgtype);
		if (mod != NULL)
			res = nmsg_pbmod_pbuf2pres(mod, np, &pres, io->endline);
		if (res != nmsg_res_success)
			return (res);
		if (io->quiet == false)
			fprintf(iopres->fp, "[%zu] %s.%09u [%d:%d %s %s] "
				"[%08x %08x] %s%s",
				np->has_payload ? np->payload.len : 0,
				when, np->time_nsec,
				np->vid, np->msgtype,
				nmsg_pbmodset_vid2vname(io->ms, np->vid),
				nmsg_pbmodset_msgtype2mname(io->ms, np->vid,
							    np->msgtype),
				np->n_user >= 1 ? np->user[0] : 0,
				np->n_user >= 2 ? np->user[1] : 0,
				io->endline, pres);
		else
			fputs(pres, iopres->fp);

		free(pres);
		iopres->count_pres_payload_out += 1;

		if (io->count > 0 && iopres->count_pres_payload_out % io->count == 0) {
			if (iopres->user != NULL) {
				ce.pres = &iopres->pres;
				ce.closetype = nmsg_io_close_type_count;
				ce.fdtype = nmsg_io_fd_type_output_pres;
				ce.io = io;
				ce.user = iopres->user;
				fclose(iopres->fp);
				io->closed_fp(&ce);
				iopres->fp = fdopen(iopres->pres->fd, "w");
				if (iopres->fp == NULL) {
					res = nmsg_res_failure;
					break;
				}
			} else {
				res = nmsg_res_stop;
				break;
			}
		}

		if (io->interval > 0 &&
		    ((unsigned) iothr->now.tv_sec - iopres->last.tv_sec)
		    >= io->interval)
		{
			if (iopres->user != NULL) {
				memcpy(&iopres->last, &iothr->now,
				       sizeof(iothr->now));
				ce.pres = &iopres->pres;
				ce.closetype = nmsg_io_close_type_interval;
				ce.fdtype = nmsg_io_fd_type_output_nmsg;
				ce.io = io;
				ce.user = iopres->user;
				fclose(iopres->fp);
				io->closed_fp(&ce);
				iopres->fp = fdopen(iopres->pres->fd, "w");
				if (iopres->fp == NULL) {
					res = nmsg_res_failure;
					break;
				}
			} else {
				res = nmsg_res_stop;
				break;
			}
		}
	}
	iopres->count_pres_out += 1;
	pthread_mutex_unlock(&iopres->lock);
	return (res);
}

static Nmsg__NmsgPayload *
make_nmsg_payload(struct nmsg_io_thr *iothr, uint8_t *pbuf, size_t sz) {
	Nmsg__NmsgPayload *np;
	struct nmsg_io *io;
	struct nmsg_io_pres *iopres;

	io = iothr->io;
	iopres = iothr->iopres;

	np = malloc(sizeof(*np));
	if (np == NULL)
		return (NULL);
	np->base.descriptor = &nmsg__nmsg_payload__descriptor;
	np->base.n_unknown_fields = 0;
	np->base.unknown_fields = NULL;
	np->vid = iopres->pres->vid;
	np->msgtype = iopres->pres->msgtype;
	np->time_sec = iothr->now.tv_sec;
	np->time_nsec = iothr->now.tv_nsec;
	np->has_payload = 1;
	np->payload.len = sz;
	np->payload.data = pbuf;
	np->n_user = io->n_user;
	np->user = io->user;

	return (np);
}

static void
init_timespec_intervals(nmsg_io io) {
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;
	struct timespec now;

	nmsg_time_get(&now);
	now.tv_nsec = 0;
	now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);

	for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
	     iobuf != NULL;
	     iobuf = ISC_LIST_NEXT(iobuf, link))
	{
		memcpy(&iobuf->last, &now, sizeof(now));
	}

	for (iopres = ISC_LIST_HEAD(io->w_pres);
	     iopres != NULL;
	     iopres = ISC_LIST_NEXT(iopres, link))
	{
		memcpy(&iopres->last, &now, sizeof(now));
	}
}
