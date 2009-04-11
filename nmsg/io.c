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

struct nmsg_io_input {
	ISC_LINK(struct nmsg_io_input)	link;
	nmsg_input_t			input;
	pthread_mutex_t			lock;
	void				*user;
	uint64_t			count_nmsg_payload_in;
};

struct nmsg_io_output {
	ISC_LINK(struct nmsg_io_output)	link;
	nmsg_output_t			output;
	pthread_mutex_t			lock;
	struct timespec			last;
	void				*user;
	uint64_t			count_nmsg_payload_out;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_input)	io_inputs;
	ISC_LIST(struct nmsg_io_output)	io_outputs;
	ISC_LIST(struct nmsg_io_thr)	threads;
	int				debug;
	nmsg_io_closed_fp		closed_fp;
	nmsg_io_output_mode		output_mode;
	pthread_mutex_t			lock;
	uint64_t			count_nmsg_payload_out;
	unsigned			count, interval;
	unsigned			n_user, user[2];
	volatile bool			stop, stopped;
};

struct nmsg_io_thr {
	ISC_LINK(struct nmsg_io_thr)	link;
	pthread_t			thr;
	nmsg_io_t			io;
	nmsg_res			res;
	struct timespec			now;
	struct nmsg_io_input		*io_input;
};

/* Forward. */

static void
init_timespec_intervals(nmsg_io_t);

static void *
io_thr_input(void *);

static nmsg_res
io_write(struct nmsg_io_thr *, struct nmsg_io_output *, Nmsg__NmsgPayload *);

static nmsg_res
io_write_mirrored(struct nmsg_io_thr *, Nmsg__NmsgPayload *);

/* Export. */

nmsg_io_t
nmsg_io_init(void) {
	struct nmsg_io *io;

	io = calloc(1, sizeof(*io));
	if (io == NULL)
		return (NULL);
	io->output_mode = nmsg_io_output_mode_stripe;
	pthread_mutex_init(&io->lock, NULL);
	ISC_LIST_INIT(io->threads);

	return (io);
}

void
nmsg_io_breakloop(nmsg_io_t io) {
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
nmsg_io_loop(nmsg_io_t io) {
	nmsg_res res;
	struct nmsg_io_input *io_input;
	struct nmsg_io_thr *iothr, *iothr_next;

	res = nmsg_res_success;

	if (io->interval > 0)
		init_timespec_intervals(io);

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
nmsg_io_destroy(nmsg_io_t *io) {
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
	free(*io);
	*io = NULL;
}

nmsg_res
nmsg_io_add_input(nmsg_io_t io, nmsg_input_t input, void *user) {
	struct nmsg_io_input *io_input;

	/* allocate */
	io_input = calloc(1, sizeof(*io_input));
	if (io_input == NULL)
		return (nmsg_res_memfail);

	/* initialize */
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
nmsg_io_add_output(nmsg_io_t io, nmsg_output_t output, void *user) {
	struct nmsg_io_output *io_output;

	/* allocate */
	io_output = calloc(1, sizeof(*io_output));
	if (io_output == NULL)
		return (nmsg_res_memfail);

	/* initialize */
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
nmsg_io_set_closed_fp(nmsg_io_t io, nmsg_io_closed_fp closed_fp) {
	io->closed_fp = closed_fp;
}

void
nmsg_io_set_count(nmsg_io_t io, unsigned count) {
	io->count = count;
}

void
nmsg_io_set_debug(nmsg_io_t io, int debug) {
	io->debug = debug;
}

void
nmsg_io_set_interval(nmsg_io_t io, unsigned interval) {
	io->interval = interval;
}

void
nmsg_io_set_output_mode(nmsg_io_t io, nmsg_io_output_mode output_mode) {
	switch (output_mode) {
	case nmsg_io_output_mode_stripe:
	case nmsg_io_output_mode_mirror:
		io->output_mode = output_mode;
	}
}

/* Private. */

static void
init_timespec_intervals(nmsg_io_t io) {
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
io_write(struct nmsg_io_thr *iothr, struct nmsg_io_output *io_output,
	 Nmsg__NmsgPayload *np)
{
	nmsg_io_t io = iothr->io;
	nmsg_res res;
	struct nmsg_io_close_event ce;

	pthread_mutex_lock(&io_output->lock);
	res = nmsg_output_write(io_output->output, np);
	pthread_mutex_unlock(&io_output->lock);

	if (!(res == nmsg_res_success ||
	      res == nmsg_res_pbuf_written))
		return (nmsg_res_failure);

	io_output->count_nmsg_payload_out += 1;

	pthread_mutex_lock(&io->lock);
	io->count_nmsg_payload_out += 1;
	pthread_mutex_unlock(&io->lock);

	res = nmsg_res_success;

	/* count check */
	if (io->count > 0 &&
	    io_output->count_nmsg_payload_out % io->count == 0)
	{
		if (io_output->user != NULL) {
			/* close notification is enabled */
			ce.io = io;
			ce.user = io_output->user;
			ce.output = &io_output->output;

			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_count;
			ce.output_type = io_output->output->type;

			nmsg_output_close(&io_output->output);
			io->closed_fp(&ce);
			if (io_output->output == NULL) {
				io->stop = true;
				return (nmsg_res_failure);
			}
		} else {
			io->stop = true;
			return (nmsg_res_stop);
		}
	}

	/* interval check */
	if (io->interval > 0 &&
	    iothr->now.tv_sec - io_output->last.tv_sec >= (time_t) io->interval)
	{
		if (io_output->user != NULL) {
			/* close notification is enabled */
			struct timespec now = iothr->now;
			now.tv_nsec = 0;
			now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);
			io_output->last = now;

			ce.io = io;
			ce.user = io_output->user;
			ce.output = &io_output->output;

			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_interval;
			ce.output_type = io_output->output->type;

			nmsg_output_close(&io_output->output);
			io->closed_fp(&ce);
			if (io_output->output == NULL) {
				io->stop = true;
				return (nmsg_res_failure);
			}
		} else {
			io->stop = true;
			return (nmsg_res_stop);
		}
	}

	return (res);
}

static nmsg_res
io_write_mirrored(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload *np) {
	Nmsg__NmsgPayload *npdup;
	nmsg_res res;
	struct nmsg_io_output *io_output;

	for (io_output = ISC_LIST_HEAD(iothr->io->io_outputs);
	     io_output != NULL;
	     io_output = ISC_LIST_NEXT(io_output, link));
	{
		npdup = nmsg_payload_dup(np);

		res = io_write(iothr, io_output, npdup);

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

	/* loop over input */
	for (;;) {
		nmsg_timespec_get(&iothr->now);
		res = nmsg_input_read(io_input->input, &np);

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
			res = io_write(iothr, io_output, np);
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
