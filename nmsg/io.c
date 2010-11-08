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
#include "nmsg_port_net.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
	nmsg_io_close_fp		close_fp;
	nmsg_io_output_mode		output_mode;
	pthread_mutex_t			lock;
	uint64_t			count_nmsg_payload_out;
	unsigned			count, interval;
	volatile bool			stop, stopped;
	nmsg_io_user_fp			atstart_fp;
	nmsg_io_user_fp			atexit_fp;
	void				*atstart_user;
	void				*atexit_user;
	unsigned			n_inputs;
	unsigned			n_outputs;
};

struct nmsg_io_thr {
	ISC_LINK(struct nmsg_io_thr)	link;
	pthread_t			thr;
	int				threadno;
	nmsg_io_t			io;
	nmsg_res			res;
	struct timespec			now;
	struct nmsg_io_input		*io_input;
};

/* Forward. */

static void
init_timespec_intervals(nmsg_io_t);

static nmsg_res
check_close_event(struct nmsg_io_thr *, struct nmsg_io_output *);

static void *
io_thr_input(void *);

static nmsg_res
io_write(struct nmsg_io_thr *, struct nmsg_io_output *, nmsg_message_t);

static nmsg_res
io_write_mirrored(struct nmsg_io_thr *, nmsg_message_t);

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
	io->stop = true;
}

nmsg_res
nmsg_io_loop(nmsg_io_t io) {
	nmsg_res res;
	struct nmsg_io_input *io_input;
	struct nmsg_io_thr *iothr, *iothr_next;
	int threadno;

	res = nmsg_res_success;

	if (io->interval > 0)
		init_timespec_intervals(io);

	threadno = 0;
	/* create io_input threads */
	for (io_input = ISC_LIST_HEAD(io->io_inputs);
	     io_input != NULL;
	     io_input = ISC_LIST_NEXT(io_input, link))
	{
		iothr = calloc(1, sizeof(*iothr));
		assert(iothr != NULL);
		iothr->io = io;
		iothr->io_input = io_input;
		iothr->threadno = threadno;
		ISC_LINK_INIT(iothr, link);
		ISC_LIST_APPEND(io->threads, iothr, link);
		assert(pthread_create(&iothr->thr, NULL, io_thr_input, iothr)
		       == 0);
		threadno += 1;
	}

	/* wait for io_input threads */
	iothr = ISC_LIST_HEAD(io->threads);
	while (iothr != NULL) {
		iothr_next = ISC_LIST_NEXT(iothr, link);
		assert(pthread_join(iothr->thr, NULL) == 0);
		if (iothr->res != nmsg_res_success &&
		    iothr->res != nmsg_res_eof &&
		    iothr->res != nmsg_res_stop)
		{
			if (io->debug >= 2)
				fprintf(stderr, "nmsg_io: iothr=%p %s\n",
					iothr, nmsg_res_lookup(iothr->res));
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
		io_input_next = ISC_LIST_NEXT(io_input, link);
		if (io_input->input != NULL && (*io)->close_fp != NULL) {
			struct nmsg_io_close_event ce;

			ce.io = *io;
			ce.io_type = nmsg_io_io_type_input;
			ce.input = &io_input->input;
			ce.input_type = io_input->input->type;
			ce.close_type = nmsg_io_close_type_eof;
			ce.user = io_input->user;

			(*io)->close_fp(&ce);
		}
		if (io_input->input != NULL) {
			nmsg_input_close(&io_input->input);
		}
		free(io_input);
		io_input = io_input_next;
	}

	/* close io_outputs */
	io_output = ISC_LIST_HEAD((*io)->io_outputs);
	while (io_output != NULL) {
		io_output_next = ISC_LIST_NEXT(io_output, link);
		if (io_output->output != NULL && (*io)->close_fp != NULL) {
			struct nmsg_io_close_event ce;

			ce.io = *io;
			ce.io_type = nmsg_io_io_type_output;
			ce.output = &io_output->output;
			ce.output_type = io_output->output->type;
			ce.close_type = nmsg_io_close_type_eof;
			ce.user = io_output->user;

			(*io)->close_fp(&ce);
		}
		if (io_output->output != NULL) {
			nmsg_output_close(&io_output->output);
		}
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

	/* increment input counter */
	io->n_inputs += 1;

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

	/* increment output counter */
	io->n_outputs += 1;

	return (nmsg_res_success);
}

static nmsg_res
_nmsg_io_add_input_socket(nmsg_io_t io, int af, char *addr, unsigned port, void *user) {
	nmsg_input_t input;
	struct sockaddr *sa;
	socklen_t salen;
	struct sockaddr_in sai;
	struct sockaddr_in6 sai6;
	int fd;
	int on = 1;
	nmsg_res res;

	if (port > 65535)
		return (nmsg_res_failure);

	res = nmsg_sock_parse(af, addr, port, &sai, &sai6, &sa, &salen);
	if (res != nmsg_res_success)
		return (res);

	fd = socket(af, SOCK_DGRAM, 0);
	if (fd < 0) {
		if (io->debug >= 2)
			fprintf(stderr, "nmsg_io: socket() failed: %s\n", strerror(errno));
		return (nmsg_res_failure);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		if (io->debug >= 2)
			fprintf(stderr, "nmsg_io: setsockopt(SO_REUSEADDR) failed: %s\n",
				strerror(errno));
		return (nmsg_res_failure);
	}

#ifdef __linux__
	if (geteuid() == 0) {
		int rcvbuf = 16777216;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
			if (io->debug >= 2)
				fprintf(stderr, "nmsg_io: setsockopt(SO_RCVBUFFORCE) failed: %s\n",
					strerror(errno));
		}
	}
#endif

	if (bind(fd, sa, salen) < 0) {
		if (io->debug >= 2)
			fprintf(stderr, "nmsg_io: bind() failed: %s\n", strerror(errno));
		return (nmsg_res_failure);
	}

	input = nmsg_input_open_sock(fd);
	if (input == NULL) {
		if (io->debug >= 2)
			fprintf(stderr, "nmsg_io: nmsg_input_open_sock() failed\n");
		return (nmsg_res_failure);
	}

	return (nmsg_io_add_input(io, input, user));
}

nmsg_res
nmsg_io_add_input_channel(nmsg_io_t io, const char *chan, void *user) {
	char **alias = NULL;
	int num_aliases;
	nmsg_res res;

	num_aliases = nmsg_chalias_lookup(chan, &alias);
	if (num_aliases <= 0) {
		if (io->debug >= 2)
			fprintf(stderr, "nmsg_io: channel alias lookup '%s' failed\n", chan);
		res = nmsg_res_failure;
		goto out;
	}
	for (int i = 0; i < num_aliases; i++) {
		int af;
		char *addr;
		unsigned port_start;
		unsigned port_end;

		res = nmsg_sock_parse_sockspec(alias[i], &af, &addr, &port_start, &port_end);
		if (res != nmsg_res_success)
			goto out;

		for (unsigned port = port_start; port <= port_end; port++) {
			res = _nmsg_io_add_input_socket(io, af, addr, port, user);
			if (res != nmsg_res_success) {
				free(addr);
				goto out;
			}
		}
		free(addr);
	}

	res = nmsg_res_success;
out:
	nmsg_chalias_free(&alias);
	return (res);
}

unsigned
nmsg_io_get_num_inputs(nmsg_io_t io) {
	return (io->n_inputs);
}

unsigned
nmsg_io_get_num_outputs(nmsg_io_t io) {
	return (io->n_outputs);
}

void
nmsg_io_set_close_fp(nmsg_io_t io, nmsg_io_close_fp close_fp) {
	io->close_fp = close_fp;
}

void
nmsg_io_set_atstart_fp(nmsg_io_t io, nmsg_io_user_fp user_fp, void *user) {
	io->atstart_fp = user_fp;
	io->atstart_user = user;
}

void
nmsg_io_set_atexit_fp(nmsg_io_t io, nmsg_io_user_fp user_fp, void *user) {
	io->atexit_fp = user_fp;
	io->atexit_user = user;
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
	 nmsg_message_t msg)
{
	nmsg_io_t io = iothr->io;
	nmsg_res res;

	if (io->close_fp == NULL) {
		res = nmsg_output_write(io_output->output, msg);
		if (io_output->output->type != nmsg_output_type_callback)
			nmsg_message_destroy(&msg);
	} else {
		pthread_mutex_lock(&io_output->lock);
		if (io_output->output == NULL) {
			pthread_mutex_unlock(&io_output->lock);
			return (nmsg_res_stop);
		}
		res = nmsg_output_write(io_output->output, msg);
		if (io_output->output->type != nmsg_output_type_callback) {
			pthread_mutex_unlock(&io_output->lock);
			nmsg_message_destroy(&msg);
		} else {
			pthread_mutex_unlock(&io_output->lock);
		}
	}

	if (res != nmsg_res_success)
		return (res);

	io_output->count_nmsg_payload_out += 1;

	pthread_mutex_lock(&io->lock);
	io->count_nmsg_payload_out += 1;
	pthread_mutex_unlock(&io->lock);

	return (res);
}

static nmsg_res
check_close_event(struct nmsg_io_thr *iothr, struct nmsg_io_output *io_output) {
	struct nmsg_io_close_event ce;
	nmsg_io_t io = iothr->io;
	nmsg_res res = nmsg_res_success;

	if (io->close_fp != NULL)
		pthread_mutex_lock(&io_output->lock);
	
	if (io_output->output == NULL) {
		res = nmsg_res_stop;
		goto out;
	}

	/* count check */
	if (io->count > 0 &&
	    io_output->count_nmsg_payload_out > 0 &&
	    io_output->count_nmsg_payload_out % io->count == 0)
	{
		if (io->close_fp != NULL) {
			/* close notification is enabled */
			ce.io = io;
			ce.user = io_output->user;
			ce.output = &io_output->output;

			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_count;
			ce.output_type = io_output->output->type;

			io->close_fp(&ce);
			if (io_output->output == NULL) {
				io->stop = true;
				res = nmsg_res_stop;
				goto out;
			}
		} else {
			io->stop = true;
			res = nmsg_res_stop;
			goto out;
		}
	}

	/* interval check */
	if (io->interval > 0 &&
	    iothr->now.tv_sec - io_output->last.tv_sec >= (time_t) io->interval)
	{
		if (io->close_fp != NULL) {
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

			io->close_fp(&ce);
			if (io_output->output == NULL) {
				io->stop = true;
				res = nmsg_res_stop;
				goto out;
			}
		} else {
			io->stop = true;
			res = nmsg_res_stop;
			goto out;
		}
	}

out:
	if (io->close_fp != NULL)
		pthread_mutex_unlock(&io_output->lock);
	return (res);
}

static nmsg_res
io_write_mirrored(struct nmsg_io_thr *iothr, nmsg_message_t msg) {
	nmsg_message_t msgdup;
	nmsg_res res;
	struct nmsg_io_output *io_output;

	res = nmsg_res_success;
	for (io_output = ISC_LIST_HEAD(iothr->io->io_outputs);
	     io_output != NULL;
	     io_output = ISC_LIST_NEXT(io_output, link))
	{
		msgdup = _nmsg_message_dup(msg);

		res = io_write(iothr, io_output, msgdup);
		if (res != nmsg_res_success)
			break;
	}
	nmsg_message_destroy(&msg);

	return (res);
}

static void *
io_thr_input(void *user) {
	nmsg_message_t msg;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_input *io_input;
	struct nmsg_io_output *io_output;
	struct nmsg_io_thr *iothr;

	msg = NULL;
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

	/* call user function */
	if (io->atstart_fp != NULL)
		io->atstart_fp(iothr->threadno, io->atstart_user);

	/* loop over input */
	for (;;) {
		nmsg_timespec_get(&iothr->now);
		res = nmsg_input_read(io_input->input, &msg);

		if (io->stop == true) {
			if (res == nmsg_res_success && msg != NULL)
				nmsg_message_destroy(&msg);
			break;
		}
		if (res == nmsg_res_again) {
			res = check_close_event(iothr, io_output);
			if (io->stop == true)
				break;
			continue;
		}
		if (res != nmsg_res_success) {
			iothr->res = res;
			break;
		}

		assert(msg != NULL);

		io_input->count_nmsg_payload_in += 1;

		if (io->output_mode == nmsg_io_output_mode_stripe)
			res = io_write(iothr, io_output, msg);
		else if (io->output_mode == nmsg_io_output_mode_mirror)
			res = io_write_mirrored(iothr, msg);

		if (res != nmsg_res_success) {
			iothr->res = res;
			break;
		}

		res = check_close_event(iothr, io_output);
		if (io->stop == true)
			break;

		io_output = ISC_LIST_NEXT(io_output, link);
		if (io_output == NULL)
			io_output = ISC_LIST_HEAD(io->io_outputs);

		if (io->stop == true)
			break;
	}

	/* call user function */
	if (io->atexit_fp != NULL)
		io->atexit_fp(iothr->threadno, io->atexit_user);

	if (io->debug >= 2)
		fprintf(stderr, "nmsg_io: iothr=%p "
			"count_nmsg_payload_in=%" PRIu64
			"\n",
			iothr,
			io_input->count_nmsg_payload_in);
	return (NULL);
}
