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
#include "io_private.h"
#include "output.h"
#include "payload.h"
#include "pbmod.h"
#include "pbmodset.h"
#include "time.h"

/* Forward. */

static void init_timespec_intervals(nmsg_io);

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
	ISC_LIST_INIT(io->iothreads);

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
	struct nmsg_io_pcap *iopcap;
	struct nmsg_io_thr *iothr, *iothr_next;

	res = nmsg_res_success;

	if (io->interval > 0)
		init_timespec_intervals(io);

	if (io->endline == NULL)
		io->endline = strdup("\n");

	/* propagate zlibout settings to nmsg writers */
	for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
	     iobuf != NULL;
	     iobuf = ISC_LIST_NEXT(iobuf, link))
	{
		nmsg_output_set_zlibout(iobuf->buf, io->zlibout);
	}

	/* create nmsg reader threads */
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
		assert(pthread_create(&iothr->thr, NULL, _nmsg_io_thr_nmsg_read,
				      iothr) == 0);
	}

	/* create pres reader threads */
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
		assert(pthread_create(&iothr->thr, NULL, _nmsg_io_thr_pres_read,
				      iothr) == 0);
	}

	/* create pcap reader threads */
	for (iopcap = ISC_LIST_HEAD(io->r_pcap);
	     iopcap != NULL;
	     iopcap = ISC_LIST_NEXT(iopcap, link))
	{
		iothr = calloc(1, sizeof(*iothr));
		assert(iothr != NULL);
		iothr->io = io;
		iothr->iopcap = iopcap;
		ISC_LINK_INIT(iothr, link);
		ISC_LIST_APPEND(io->iothreads, iothr, link);
		assert(pthread_create(&iothr->thr, NULL, _nmsg_io_thr_pcap_read,
				      iothr) == 0);
	}

	/* wait for reader threads */
	iothr = ISC_LIST_HEAD(io->iothreads);
	while (iothr != NULL) {
		iothr_next = ISC_LIST_NEXT(iothr, link);
		assert(pthread_join(iothr->thr, NULL) == 0);
		if (iothr->res != nmsg_res_success) {
			if (io->debug >= 2)
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
	struct nmsg_io_pcap *iopcap, *iopcap_next;

	ce.buf = NULL;
	ce.closetype = nmsg_io_close_type_eof;
	ce.io = *io;

	/* close nmsg readers */
	iobuf = ISC_LIST_HEAD((*io)->r_nmsg);
	while (iobuf != NULL) {
		iobuf_next = ISC_LIST_NEXT(iobuf, link);
		nmsg_input_close(&iobuf->buf);
		if ((*io)->closed_fp != NULL) {
			ce.fdtype = nmsg_io_fd_type_input_nmsg;
			ce.user = iobuf->user;
			(*io)->closed_fp(&ce);
		}
		free(iobuf);
		iobuf = iobuf_next;
	}

	/* close nmsg writers */
	iobuf = ISC_LIST_HEAD((*io)->w_nmsg);
	while (iobuf != NULL) {
		iobuf_next = ISC_LIST_NEXT(iobuf, link);
		if ((*io)->closed_fp != NULL) {
			ce.fdtype = nmsg_io_fd_type_output_nmsg;
			ce.user = iobuf->user;
			(*io)->closed_fp(&ce);
		}
		res = nmsg_output_close(&iobuf->buf);
		if (res == nmsg_res_pbuf_written) {
			pthread_mutex_lock(&(*io)->lock);
			(*io)->count_nmsg_out += 1;
			pthread_mutex_unlock(&(*io)->lock);
		}
		free(iobuf);
		iobuf = iobuf_next;
	}

	/* close pres readers */
	iopres = ISC_LIST_HEAD((*io)->r_pres);
	while (iopres != NULL) {
		iopres_next = ISC_LIST_NEXT(iopres, link);
		if ((*io)->closed_fp != NULL) {
			ce.fdtype = nmsg_io_fd_type_input_pres;
			ce.user = iopres->user;
			(*io)->closed_fp(&ce);
		}
		fclose(iopres->fp);
		nmsg_output_close_pres(&iopres->pres);
		free(iopres);
		iopres = iopres_next;
	}

	/* close pres writers */
	iopres = ISC_LIST_HEAD((*io)->w_pres);
	while (iopres != NULL) {
		iopres_next = ISC_LIST_NEXT(iopres, link);
		if ((*io)->closed_fp != NULL) {
			ce.fdtype = nmsg_io_fd_type_output_pres;
			ce.user = iopres->user;
			(*io)->closed_fp(&ce);
		}
		fclose(iopres->fp);
		nmsg_output_close_pres(&iopres->pres);
		free(iopres);
		iopres = iopres_next;
	}

	/* close pcap readers */
	iopcap = ISC_LIST_HEAD((*io)->r_pcap);
	while (iopcap != NULL) {
		iopcap_next = ISC_LIST_NEXT(iopcap, link);
		nmsg_input_close_pcap(&iopcap->pcap);
		free(iopcap);
		iopcap = iopcap_next;
	}

	/* print statistics */
	if ((*io)->debug >= 2 && (*io)->count_nmsg_out > 0)
		fprintf(stderr, "nmsg_io: io=%p"
			" count_nmsg_out=%" PRIu64
			" count_nmsg_payload_out=%" PRIu64
			"\n",
			(*io),
			(*io)->count_nmsg_out,
			(*io)->count_nmsg_payload_out);
	if ((*io)->debug >= 2 && (*io)->count_pres_out > 0)
		fprintf(stderr, "nmsg_io: io=%p"
			" count_pres_out=%" PRIu64
			" count_pres_payload_out=%" PRIu64
			"\n",
			(*io),
			(*io)->count_pres_out,
			(*io)->count_pres_payload_out);

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

nmsg_res
nmsg_io_add_pcap(nmsg_io io, nmsg_pbmod mod, nmsg_pcap pcap) {
	struct nmsg_io_pcap *iopcap;

	iopcap = calloc(1, sizeof(*iopcap));
	if (iopcap == NULL)
		return (nmsg_res_memfail);
	iopcap->pcap = pcap;
	iopcap->mod = mod;

	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->r_pcap, iopcap, link);
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
