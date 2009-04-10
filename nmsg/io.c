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

#include "isc_list.h"

#include "nmsg.h"
#include "private.h"

/* Private declarations. */

struct nmsg_io;
struct nmsg_io_input;
struct nmsg_io_output;
struct nmsg_io_thr;

typedef nmsg_res (*io_input_read_fp)(struct nmsg_io_thr *,
				     Nmsg__NmsgPayload **);
typedef nmsg_res (*io_output_write_fp)(struct nmsg_io_thr *,
				       struct nmsg_io_output *,
				       Nmsg__NmsgPayload **);

struct nmsg_io_input {
	ISC_LINK(struct nmsg_io_input)	link;
	nmsg_input			input;
	pthread_mutex_t			lock;
	void				*clos, *user;
	uint64_t			count_nmsg_payload_in;
	nmsg_pbmod			pbmod;
	io_input_read_fp		read_fp;
};

struct nmsg_io_output {
	ISC_LINK(struct nmsg_io_output)	link;
	nmsg_output			output;
	pthread_mutex_t			lock;
	struct timespec			last;
	void				*user;
	uint64_t			count_nmsg_payload_out;
	io_output_write_fp		write_fp;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_input)	io_inputs;
	ISC_LIST(struct nmsg_io_output)	io_outputs;
	ISC_LIST(struct nmsg_io_thr)	threads;
	bool				quiet, zlibout;
	char				*endline;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	nmsg_io_output_mode		output_mode;
	nmsg_pbmodset			ms;
	pthread_mutex_t			lock;
	uint64_t			count_nmsg_payload_out;
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
	struct nmsg_io_input		*io_input;
};

/* Forward. */

static void
init_timespec_intervals(nmsg_io);

static void *
io_thr_input(void *);

static nmsg_res
io_write_mirrored(struct nmsg_io_thr *, Nmsg__NmsgPayload *);

static nmsg_res
io_write_payload_nmsg(struct nmsg_io_thr *, struct nmsg_io_output *,
		      Nmsg__NmsgPayload **);

static nmsg_res
io_write_payload_pres(struct nmsg_io_thr *, struct nmsg_io_output *,
		      Nmsg__NmsgPayload **);

static nmsg_res
io_read_payload_nmsg(struct nmsg_io_thr *, Nmsg__NmsgPayload **);

static nmsg_res
io_read_payload_pcap(struct nmsg_io_thr *, Nmsg__NmsgPayload **);

static nmsg_res
io_read_payload_pres(struct nmsg_io_thr *, Nmsg__NmsgPayload **);

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
	ISC_LIST_INIT(io->threads);

	return (io);
}

void
nmsg_io_breakloop(nmsg_io io) {
	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };

	io->stop = true;
	nmsg_timespec_sleep(&ts);
	if (io->stopped != true) {
		struct nmsg_io_thr *iothr;

		for (iothr = ISC_LIST_HEAD(io->threads);
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
	struct nmsg_io_input *io_input;
	struct nmsg_io_output *io_output;
	struct nmsg_io_thr *iothr, *iothr_next;

	res = nmsg_res_success;

	if (io->interval > 0)
		init_timespec_intervals(io);

	if (io->endline == NULL)
		io->endline = strdup("\n");

	/* propagate zlibout settings to nmsg writers */
	for (io_output = ISC_LIST_HEAD(io->io_outputs);
	     io_output !=NULL;
	     io_output = ISC_LIST_NEXT(io_output, link))
	{
		nmsg_output_set_zlibout(io_output->output, io->zlibout);
	}

	/* create io_input threads */
	for (io_input = ISC_LIST_HEAD(io->io_inputs);
	     io_input != NULL;
	     io_input = ISC_LIST_NEXT(io_input, link))
	{
		iothr = calloc(1, sizeof(*iothr));
		assert(iothr != NULL);
		iothr->io = io;
		iothr->io_input = io_input;
		ISC_LINK_INIT(iothr, link);
		ISC_LIST_APPEND(io->threads, iothr, link);
		assert(pthread_create(&iothr->thr, NULL, io_thr_input, iothr)
		       == 0);
	}

	/* wait for io_input threads */
	iothr = ISC_LIST_HEAD(io->threads);
	while (iothr != NULL) {
		iothr_next = ISC_LIST_NEXT(iothr, link);
		assert(pthread_join(iothr->thr, NULL) == 0);
		if (iothr->res != nmsg_res_success) {
			if (io->debug >= 2)
				fprintf(stderr, "nmsg_io: iothr=%p res=%d\n",
					iothr, (int) iothr->res);
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
	struct nmsg_io_input *io_input, *io_input_next;
	struct nmsg_io_output *io_output, *io_output_next;

	/* close io_inputs */
	io_input = ISC_LIST_HEAD((*io)->io_inputs);
	while (io_input != NULL) {
		struct nmsg_io_close_event ce;
		ce.io = *io;
		ce.io_type = nmsg_io_io_type_input;
		ce.input = NULL;
		ce.input_type = io_input->input->type;
		ce.close_type = nmsg_io_close_type_eof;
		ce.user = io_input->user;

		io_input_next = ISC_LIST_NEXT(io_input, link);
		nmsg_input_close(&io_input->input);
		if ((*io)->closed_fp != NULL)
			(*io)->closed_fp(&ce);
		if (io_input->pbmod != NULL)
			nmsg_pbmod_fini(io_input->pbmod, &io_input->clos);
		free(io_input);
		io_input = io_input_next;
	}

	/* close io_outputs */
	io_output = ISC_LIST_HEAD((*io)->io_outputs);
	while (io_output != NULL) {
		struct nmsg_io_close_event ce;
		ce.io = *io;
		ce.io_type = nmsg_io_io_type_output;
		ce.output = NULL;
		ce.output_type = io_output->output->type;
		ce.close_type = nmsg_io_close_type_eof;
		ce.user = io_output->user;

		io_output_next = ISC_LIST_NEXT(io_output, link);
		nmsg_output_close(&io_output->output);
		if ((*io)->closed_fp != NULL)
			(*io)->closed_fp(&ce);
		free(io_output);
		io_output = io_output_next;
	}

	/* print statistics */
	if ((*io)->debug >= 2 && (*io)->count_nmsg_payload_out > 0)
		fprintf(stderr, "nmsg_io: io=%p"
			" count_nmsg_payload_out=%" PRIu64
			"\n",
			(*io),
			(*io)->count_nmsg_payload_out);
	free((*io)->endline);
	free(*io);
	*io = NULL;
}

nmsg_res
nmsg_io_add_input(nmsg_io io, nmsg_input input, void *user) {
	struct nmsg_io_input *io_input;

	/* allocate */
	io_input = calloc(1, sizeof(*io_input));
	if (io_input == NULL)
		return (nmsg_res_memfail);

	/* initialize */
	switch (input->type) {
	case nmsg_input_type_stream:
		io_input->read_fp = io_read_payload_nmsg;
		break;
	case nmsg_input_type_pcap:
		io_input->read_fp = io_read_payload_pcap;
		io_input->pbmod = input->pcap->pbmod;
		break;
	case nmsg_input_type_pres:
		io_input->read_fp = io_read_payload_pres;
		io_input->pbmod = input->pres->pbmod;
		break;
	default:
		free(io_input);
		return (nmsg_res_failure);
	}
	io_input->input = input;
	io_input->user = user;
	pthread_mutex_init(&io_input->lock, NULL);

	/* add to nmsg_io input list */
	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->io_inputs, io_input, link);
	pthread_mutex_unlock(&io->lock);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_output(nmsg_io io, nmsg_output output, void *user) {
	struct nmsg_io_output *io_output;

	/* allocate */
	io_output = calloc(1, sizeof(*io_output));
	if (io_output == NULL)
		return (nmsg_res_memfail);

	/* initialize */
	switch (output->type) {
	case nmsg_output_type_stream:
		io_output->write_fp = io_write_payload_nmsg;
		break;
	case nmsg_output_type_pres:
		io_output->write_fp = io_write_payload_pres;
		break;
	default:
		free(io_output);
		return (nmsg_res_failure);
	}
	io_output->output = output;
	io_output->user = user;
	pthread_mutex_init(&io_output->lock, NULL);

	/* add to nmsg_io output list */
	pthread_mutex_lock(&io->lock);
	ISC_LIST_APPEND(io->io_outputs, io_output, link);
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
	struct nmsg_io_output *io_output;
	struct timespec now;

	nmsg_timespec_get(&now);
	now.tv_nsec = 0;
	now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);

	for (io_output = ISC_LIST_HEAD(io->io_outputs);
	     io_output != NULL;
	     io_output = ISC_LIST_NEXT(io_output, link))
	{
		io_output->last = now;
	}
}

static nmsg_res
io_write_payload_nmsg(struct nmsg_io_thr *iothr,
		      struct nmsg_io_output *io_output,
		      Nmsg__NmsgPayload **np)
{
	nmsg_io io;
	nmsg_res res;
	struct nmsg_io_close_event ce;

	io = iothr->io;

	if (io->n_user > 0) {
		size_t user_bytes = io->n_user * sizeof(*((*np)->user));
		(*np)->user = malloc(user_bytes);
		if ((*np)->user == NULL)
			return (nmsg_res_memfail);
		memcpy((*np)->user, io->user, user_bytes);
		(*np)->n_user = io->n_user;
	}

	res = nmsg_output_append(io_output->output, *np);
	if (!(res == nmsg_res_success ||
	      res == nmsg_res_pbuf_written))
		return (nmsg_res_failure);

	io_output->count_nmsg_payload_out += 1;

	pthread_mutex_lock(&io->lock);
	io->count_nmsg_payload_out += 1;
	pthread_mutex_unlock(&io->lock);

	res = nmsg_res_success;

	if (io->count > 0 &&
	    io_output->count_nmsg_payload_out % io->count == 0)
	{
		if (io_output->user != NULL) {
			ce.io = io;
			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_count;
			ce.output_type = io_output->output->type;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			nmsg_output_set_zlibout(io_output->output, io->zlibout);
		} else {
			io->stop = true;
			res = nmsg_res_stop;
		}
	}

	if (io->interval > 0 &&
	    (iothr->now.tv_sec - io_output->last.tv_sec) >=
		    (time_t) io->interval)
	{
		if (io_output->user != NULL) {
			struct timespec now = iothr->now;
			now.tv_nsec = 0;
			now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);
			io_output->last = now;

			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_interval;
			ce.io = io;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			nmsg_output_set_zlibout(io_output->output, io->zlibout);
		} else {
			io->stop = true;
			res = nmsg_res_stop;
		}
	}
	return (res);
}

static nmsg_res
io_write_payload_pres(struct nmsg_io_thr *iothr,
		      struct nmsg_io_output *io_output,
		      Nmsg__NmsgPayload **np)
{
	char *pres_data;
	char when[32];
	nmsg_pbmod mod;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_close_event ce;
	struct nmsg_pres *pres;
	struct tm *tm;
	time_t t;

	pres = io_output->output->pres;
	io = iothr->io;
	t = (*np)->time_sec;
	tm = gmtime(&t);
	strftime(when, sizeof(when), "%Y-%m-%d %T", tm);
	mod = nmsg_pbmodset_lookup(io->ms, (*np)->vid, (*np)->msgtype);
	if (mod != NULL) {
		res = nmsg_pbmod_pbuf_to_pres(mod, *np, &pres_data,
					      io->endline);
		if (res != nmsg_res_success)
			return (res);
	} else {
		nmsg_asprintf(&pres_data, "<UNKNOWN NMSG %u:%u>%s",
			      (*np)->vid, (*np)->msgtype,
			      io->endline);
	}
	if (io->quiet == false)
		fprintf(pres->fp, "[%zu] %s.%09u [%d:%d %s %s] "
			"[%08x %08x] %s%s",
			(*np)->has_payload ? (*np)->payload.len : 0,
			when, (*np)->time_nsec,
			(*np)->vid, (*np)->msgtype,
			nmsg_pbmodset_vid_to_vname(io->ms, (*np)->vid),
			nmsg_pbmodset_msgtype_to_mname(io->ms, (*np)->vid,
						       (*np)->msgtype),
			(*np)->n_user >= 1 ? (*np)->user[0] : 0,
			(*np)->n_user >= 2 ? (*np)->user[1] : 0,
			io->endline, pres_data);
	else
		fputs(pres_data, pres->fp);
	fputs(io->endline, pres->fp);
	free(pres_data);

	io_output->count_nmsg_payload_out += 1;

	res = nmsg_res_success;

	if (io->count > 0 &&
	    io_output->count_nmsg_payload_out % io->count == 0)
	{
		if (io_output->user != NULL) {
			ce.io_type = nmsg_io_io_type_output;
			ce.output_type = io_output->output->type;
			ce.close_type = nmsg_io_close_type_count;
			ce.io = io;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			if (io_output->output == NULL) {
				res = nmsg_res_failure;
				goto out;
			}
		} else {
			io->stop = true;
			res = nmsg_res_stop;
			goto out;
		}
	}

	if (io->interval > 0 &&
	    iothr->now.tv_sec - io_output->last.tv_sec >= (time_t) io->interval)
	{
		if (io_output->user != NULL) {
			struct timespec now = iothr->now;
			now.tv_nsec = 0;
			now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);
			io_output->last = now;

			ce.io_type = nmsg_io_io_type_output;
			ce.output_type = io_output->output->type;
			ce.close_type = nmsg_io_close_type_interval;
			ce.io = io;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			if (io_output->output->pres->fp == NULL) {
				res = nmsg_res_failure;
				goto out;
			}
		} else {
			io->stop = true;
			res = nmsg_res_stop;
			goto out;
		}
	}

out:
	nmsg_payload_free(np);
	return (res);
}

static nmsg_res
io_read_payload_nmsg(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload **np) {
	return (nmsg_input_next(iothr->io_input->input, np));
}

static nmsg_res
io_read_payload_pcap(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload **np)
{
	nmsg_res res;
	size_t sz;
	struct nmsg_ipdg dg;
	uint8_t *pbuf;
	unsigned vid, msgtype;
	struct nmsg_io_input *io_input = iothr->io_input;

	/* get next ip datagram from pcap source */
	res = nmsg_pcap_input_next(io_input->input->pcap, &dg);
	if (res != nmsg_res_success)
		return (res);

	/* convert ip datagram to protobuf payload */
	res = nmsg_pbmod_ipdg_to_pbuf(io_input->input->pcap->pbmod,
				      io_input->clos, &dg, &pbuf, &sz,
				      &vid, &msgtype);
	if (res != nmsg_res_pbuf_ready)
		return (res);

	/* convert protobuf data to nmsg payload */
	*np = nmsg_payload_make(pbuf, sz, vid, msgtype, &iothr->now);
	if (*np == NULL) {
		free(pbuf);
		return (nmsg_res_memfail);
	}

	return (nmsg_res_success);
}

static nmsg_res
io_read_payload_pres(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload **np)
{
	char line[1024];
	nmsg_res res;
	size_t sz;
	uint8_t *pbuf;
	unsigned vid, msgtype;
	struct nmsg_io_input *io_input = iothr->io_input;

	vid = io_input->pbmod->vendor.id;
	msgtype = io_input->pbmod->msgtype.id;

	while (fgets(line, sizeof(line), io_input->input->pres->fp) != NULL) {
		res = nmsg_pbmod_pres_to_pbuf(io_input->pbmod, io_input->clos,
					      line);
		if (res == nmsg_res_failure)
			return (res);
		if (res == nmsg_res_success)
			continue;
		if (res != nmsg_res_pbuf_ready)
			return (res);

		/* pbuf now ready, finalize and convert to nmsg payload */
		res = nmsg_pbmod_pres_to_pbuf_finalize(io_input->pbmod,
						       io_input->clos,
						       &pbuf, &sz);
		if (res != nmsg_res_success)
			return (res);
		*np = nmsg_payload_make(pbuf, sz, vid, msgtype, &iothr->now);
		if (*np == NULL) {
			free(pbuf);
			return (nmsg_res_memfail);
		}

		return (nmsg_res_success);
	}

	return (nmsg_res_failure);
}

static nmsg_res
io_write_mirrored(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload *np) {
	Nmsg__NmsgPayload *npdup;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_output *io_output;

	io = iothr->io;

	for (io_output = ISC_LIST_HEAD(io->io_outputs);
	     io_output != NULL;
	     io_output = ISC_LIST_NEXT(io_output, link));
	{
		npdup = nmsg_payload_dup(np);

		pthread_mutex_lock(&io_output->lock);
		res = io_output->write_fp(iothr, io_output, &npdup);
		pthread_mutex_unlock(&io_output->lock);

		if (res != nmsg_res_success) {
			nmsg_payload_free(&npdup);
			nmsg_payload_free(&np);
			return (res);
		}
	}
	nmsg_payload_free(&np);

	return (nmsg_res_success);
}

static void *
io_thr_input(void *user) {
	Nmsg__NmsgPayload *np = NULL;
	bool duplicate;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_input *io_input;
	struct nmsg_io_output *io_output;
	struct nmsg_io_thr *iothr;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	io_input = iothr->io_input;
	io_output = ISC_LIST_HEAD(io->io_outputs);

	if (io->debug >= 4)
		fprintf(stderr, "nmsg_io: started input thread @ %p\n", iothr);

	/* sanity checks */
	if (io_output == NULL) {
		fprintf(stderr, "nmsg_io: no outputs\n");
		iothr->res = nmsg_res_failure;
		return (NULL);
	}

	/* initialize 'duplicate' */
	switch (io->output_mode) {
	case nmsg_io_output_mode_stripe:
		duplicate = false;
		break;
	case nmsg_io_output_mode_mirror:
		duplicate = true;
		break;
	default:
		fprintf(stderr, "nmsg_io: unknown output mode %d\n",
			io->output_mode);
		iothr->res = nmsg_res_failure;
		return (NULL);
	}

	/* initialize io_input->clos if necessary */
	if (io_input->pbmod != NULL) {
		res = nmsg_pbmod_init(io_input->pbmod, &io_input->clos, io->debug);
		if (res != nmsg_res_success) {
			free(io_input);
			iothr->res = res;
			return (NULL);
		}
	}

	/* loop over input */
	for (;;) {
		res = io_input->read_fp(iothr, &np);
		nmsg_timespec_get(&iothr->now);

		if (io->stop == true && np == NULL)
			break;
		if (res == nmsg_res_again)
			continue;
		if (res != nmsg_res_success) {
			iothr->res = res;
			break;
		}

		assert(np != NULL);

		io_input->count_nmsg_payload_in += 1;

		if (io->output_mode == nmsg_io_output_mode_stripe)
			res = io_output->write_fp(iothr, io_output, &np);
		else if (io->output_mode == nmsg_io_output_mode_mirror)
			res = io_write_mirrored(iothr, np);

		if (res != nmsg_res_success) {
			iothr->res = res;
			break;
		}

		io_output = ISC_LIST_NEXT(io_output, link);
		if (io_output == NULL)
			io_output = ISC_LIST_HEAD(io->io_outputs);

		if (io->stop == true)
			break;
	}

	if (io->debug >= 2)
		fprintf(stderr, "nmsg_io: iothr=%p "
			"count_nmsg_payload_in=%" PRIu64
			"\n",
			iothr,
			io_input->count_nmsg_payload_in);
	return (NULL);
}
