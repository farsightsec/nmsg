/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2008-2021 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

#include "private.h"

/* Private declarations. */

struct nmsg_io;
struct nmsg_io_filter;
struct nmsg_io_input;
struct nmsg_io_output;
struct nmsg_io_thr;

typedef enum {
	nmsg_io_filter_type_function,
	nmsg_io_filter_type_module,
} nmsg_io_filter_type;

struct nmsg_io_filter {
	nmsg_io_filter_type		type;
	union {
		nmsg_filter_message_fp	fp;
		nmsg_fltmod_t		mod;
	};
	void				*data;
};
VECTOR_GENERATE(nmsg_io_filter_vec, struct nmsg_io_filter *)

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
	pthread_cond_t			wait_cond;	/* bcast !closing */
	pthread_cond_t			close_cond;	/* signal refcount==0 */
	bool				closing;	/* close_fp() pending */
	/* Incremented in check_close_event(); decr'ed in reset_close_event() */
	int				refcount;
	struct timespec			last;		/* for intervals */
	void				*user;
	uint64_t			count_nmsg_payload_out;
	/* absolute counter that avoids a simpler but more expensive modulo */
	uint64_t			count_next_close;
};

struct nmsg_io {
	ISC_LIST(struct nmsg_io_input)	io_inputs;
	ISC_LIST(struct nmsg_io_output)	io_outputs;
	ISC_LIST(struct nmsg_io_thr)	threads;
	int				debug;
	nmsg_io_close_fp		close_fp;
	nmsg_io_output_mode		output_mode;
	pthread_mutex_t			lock;
	atomic_uint_fast64_t		io_count_nmsg_payload_out;
	unsigned			count, interval, interval_offset;
	bool                            interval_randomized;
	volatile bool			stop;
	nmsg_io_user_fp			atstart_fp;
	nmsg_io_user_fp			atexit_fp;
	void				*atstart_user;
	void				*atexit_user;
	unsigned			n_inputs;
	unsigned			n_outputs;
	nmsg_io_filter_vec		*filters;
	nmsg_filter_message_verdict	filter_policy;
};

struct nmsg_io_thr {
	ISC_LINK(struct nmsg_io_thr)	link;
	pthread_t			thr;
	int				threadno;
	nmsg_io_t			io;
	nmsg_res			res;
	struct timespec			now;
	struct nmsg_io_input		*io_input;
	nmsg_io_filter_vec		*filters;
};

/* Forward. */

static void
init_timespec_intervals(nmsg_io_t);

static void
check_close_event(struct nmsg_io_thr *, struct nmsg_io_output *, uint64_t);

static void
call_close_fp(struct nmsg_io_thr *, struct nmsg_io_output *, struct nmsg_io_close_event *);

static void
reset_close_event(struct nmsg_io_thr *, struct nmsg_io_output *);

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
	io->filters = nmsg_io_filter_vec_init(1);
	io->filter_policy = nmsg_filter_message_verdict_ACCEPT;

	return (io);
}

nmsg_res
nmsg_io_get_stats(nmsg_io_t io, uint64_t *sum_in, uint64_t *sum_out,
		uint64_t *container_recvs, uint64_t *container_drops) {
	struct nmsg_io_input *io_input;

	if (io == NULL || sum_in == NULL || sum_out == NULL ||
		container_recvs == NULL || container_drops == NULL)
		return nmsg_res_failure;

	*sum_in = 0;

	for (io_input = ISC_LIST_HEAD(io->io_inputs);
		 io_input != NULL;
		 io_input = ISC_LIST_NEXT(io_input, link))
	{
		uint64_t drops = 0, recvs = 0;

		if (io_input->input != NULL &&
			(nmsg_input_get_count_container_received(io_input->input, &recvs) == nmsg_res_failure ||
			nmsg_input_get_count_container_dropped(io_input->input, &drops) == nmsg_res_failure))
			continue;

		*sum_in += io_input->count_nmsg_payload_in;
		*container_drops += drops;
		*container_recvs += recvs;
	}

	*sum_out = atomic_load_explicit(&io->io_count_nmsg_payload_out, memory_order_relaxed);

	return nmsg_res_success;
}

void
nmsg_io_breakloop(nmsg_io_t io) {
	struct nmsg_io_output *io_output;
	struct nmsg_io_input *io_input;

	if (io == NULL)
		return;
	if (io->stop)
		return;

	io->stop = true;
	for (io_output = ISC_LIST_HEAD(io->io_outputs);
	     io_output != NULL;
	     io_output = ISC_LIST_NEXT(io_output, link))
	{
		if (io_output->output != NULL)
			_output_stop(io_output->output);
	}
	for (io_input = ISC_LIST_HEAD(io->io_inputs);
		 io_input != NULL;
		 io_input = ISC_LIST_NEXT(io_input, link))
	{
		if (io_input->input != NULL)
			_input_stop(io_input->input);
	}
}

nmsg_res
nmsg_io_loop(nmsg_io_t io) {
	nmsg_res res;
	struct nmsg_io_input *io_input;
	struct nmsg_io_thr *iothr, *iothr_next;
	int pthread_res;
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
		pthread_res = pthread_create(&iothr->thr, NULL, io_thr_input, iothr);
		assert (pthread_res == 0);
		threadno += 1;
	}

	/* wait for io_input threads */
	iothr = ISC_LIST_HEAD(io->threads);
	while (iothr != NULL) {
		iothr_next = ISC_LIST_NEXT(iothr, link);
		pthread_res = pthread_join(iothr->thr, NULL);
		assert (pthread_res == 0);
		if (iothr->res != nmsg_res_success &&
		    iothr->res != nmsg_res_eof &&
		    iothr->res != nmsg_res_stop)
		{
			_nmsg_dprintfv(io->debug, 2, "nmsg_io: iothr=%p %s\n",
				       (void *)iothr, nmsg_res_lookup(iothr->res));
			res = nmsg_res_failure;
		}
		free(iothr);
		iothr = iothr_next;
	}

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
		pthread_cond_destroy(&io_output->wait_cond);
		pthread_cond_destroy(&io_output->close_cond);
		pthread_mutex_destroy(&io_output->lock);
		free(io_output);
		io_output = io_output_next;
	}

	/* destroy filters */
	for (size_t i = 0; i < nmsg_io_filter_vec_size((*io)->filters); i++) {
		struct nmsg_io_filter *filter =
			nmsg_io_filter_vec_value((*io)->filters, i);

		switch (filter->type) {
		case nmsg_io_filter_type_function:
			break;
		case nmsg_io_filter_type_module:
			nmsg_fltmod_destroy(&filter->mod);
			break;
		}

		my_free(filter);
	}
	nmsg_io_filter_vec_destroy(&(*io)->filters);

	/* print statistics */
	if ((*io)->debug >= 2) {
		uint64_t pl_out = atomic_load_explicit(&(*io)->io_count_nmsg_payload_out, memory_order_relaxed);

		if (pl_out > 0)
			_nmsg_dprintfv((*io)->debug, 2, "nmsg_io: io=%p"
				       " count_nmsg_payload_out=%" PRIu64 "\n",
				       (void *)(*io), pl_out);
	}
	free(*io);
	*io = NULL;
}

nmsg_res
nmsg_io_add_filter(nmsg_io_t io, nmsg_filter_message_fp fp, void *data) {
	/* Wrap the callback in an io_filter. */
	struct nmsg_io_filter *filter = my_calloc(1, sizeof(*filter));
	filter->type = nmsg_io_filter_type_function;
	filter->fp = *fp;
	filter->data = data;

	/* Add to the global filter vector. */
	nmsg_io_filter_vec_add(io->filters, filter);

	return nmsg_res_success;
}

nmsg_res
nmsg_io_add_filter_module(nmsg_io_t io, const char *name,
			  const void *param, const size_t len_param)
{
	/* Initialize the filter module. */
	nmsg_fltmod_t fltmod = nmsg_fltmod_init(name, param, len_param);
	if (fltmod == NULL) {
		_nmsg_dprintf(4, "%s: nmsg_fltmod_init() failed\n", __func__);
		return nmsg_res_failure;
	}

	/* Wrap the fltmod in an io_filter. */
	struct nmsg_io_filter *filter = my_calloc(1, sizeof(*filter));
	filter->type = nmsg_io_filter_type_module;
	filter->mod = fltmod;

	/* Add to the global filter vector. */
	nmsg_io_filter_vec_add(io->filters, filter);

	return nmsg_res_success;
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
	pthread_cond_init(&io_output->wait_cond, NULL);
	pthread_cond_init(&io_output->close_cond, NULL);

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
		_nmsg_dprintfv(io->debug, 2, "nmsg_io: socket() failed: %s\n", strerror(errno));
		return (nmsg_res_failure);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		_nmsg_dprintfv(io->debug, 2, "nmsg_io: setsockopt(SO_REUSEADDR) failed: %s\n",
			       strerror(errno));
		return (nmsg_res_failure);
	}

#ifdef __linux__
# ifdef SO_RCVBUFFORCE
	if (geteuid() == 0) {
		int rcvbuf = 16777216;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
			_nmsg_dprintfv(io->debug, 2,
				       "nmsg_io: setsockopt(SO_RCVBUFFORCE) failed: %s\n",
					strerror(errno));
		}
	}
# endif
#endif

	if (bind(fd, sa, salen) < 0) {
		_nmsg_dprintfv(io->debug, 2,
			       "nmsg_io: bind() failed: %s\n", strerror(errno));
		return (nmsg_res_failure);
	}

	input = nmsg_input_open_sock(fd);
	if (input == NULL) {
		_nmsg_dprintfv(io->debug, 2, "%s", "nmsg_io: nmsg_input_open_sock() failed\n");
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
		_nmsg_dprintfv(io->debug, 2, "nmsg_io: channel alias lookup '%s' failed\n", chan);
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

#ifdef HAVE_LIBZMQ
static nmsg_res
_nmsg_io_add_input_zmq(nmsg_io_t io, void *zmq_ctx, const char *str_socket, void *user) {
	nmsg_input_t input;

	input = nmsg_input_open_zmq_endpoint(zmq_ctx, str_socket);
	if (input == NULL) {
		_nmsg_dprintfv(io->debug, 2, "%s", "nmsg_io: nmsg_input_open_zmq_endpoint() failed\n");
		return (nmsg_res_failure);
	}
	return (nmsg_io_add_input(io, input, user));
}
#endif /* HAVE_LIBZMQ */

#ifdef HAVE_LIBZMQ
nmsg_res
nmsg_io_add_input_zmq_channel(nmsg_io_t io, void *zmq_ctx, const char *chan, void *user) {
	char **alias = NULL;
	int num_aliases;
	nmsg_res res;

	num_aliases = nmsg_chalias_lookup(chan, &alias);
	if (num_aliases <= 0) {
		_nmsg_dprintfv(io->debug, 2,
			       "nmsg_io: ZMQ channel alias lookup '%s' failed\n", chan);
		res = nmsg_res_failure;
		goto out;
	}
	for (int i = 0; i < num_aliases; i++) {
		res = _nmsg_io_add_input_zmq(io, zmq_ctx, alias[i], user);
		if (res != nmsg_res_success)
			goto out;
	}

	res = nmsg_res_success;
out:
	nmsg_chalias_free(&alias);
	return (res);
}
#else /* HAVE_LIBZMQ */
nmsg_res
nmsg_io_add_input_zmq_channel(nmsg_io_t io,
			     void *zmq_ctx __attribute__((unused)),
			     const char *chan __attribute__((unused)),
			     void *user __attribute__((unused)))
{
	_nmsg_dprintfv(io->debug, 2, "nmsg_io: %s: compiled without libzmq support\n", __func__);
	return (nmsg_res_failure);
}
#endif /* HAVE_LIBZMQ */

nmsg_res
nmsg_io_add_input_sockspec(nmsg_io_t io, const char *sockspec, void *user) {
	int af;
	char *addr;
	unsigned port_start;
	unsigned port_end;
	nmsg_res res;

	res = nmsg_sock_parse_sockspec(sockspec, &af, &addr, &port_start, &port_end);
	if (res != nmsg_res_success)
		return (res);

	for (unsigned port = port_start; port <= port_end; port++) {
		res = _nmsg_io_add_input_socket(io, af, addr, port, user);
		if (res != nmsg_res_success) {
			free(addr);
			return (res);
		}
	}
	free(addr);

	return (nmsg_res_success);
}

nmsg_res
nmsg_io_add_input_fname(nmsg_io_t io, const char *fname, void *user) {
	int fd;
	nmsg_input_t input;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		_nmsg_dprintfv(io->debug, 2, "nmsg_io: open() failed: %s\n", strerror(errno));
		return (nmsg_res_failure);
	}

	input = nmsg_input_open_file(fd);
	if (input == NULL) {
		close(fd);
		_nmsg_dprintfv(io->debug, 2, "%s", "nmsg_io: nmsg_input_open_file() failed\n");
		return (nmsg_res_failure);
	}

	return (nmsg_io_add_input(io, input, user));
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
nmsg_io_set_filter_policy(nmsg_io_t io, const nmsg_filter_message_verdict policy) {
	if (policy == nmsg_filter_message_verdict_ACCEPT ||
	    policy == nmsg_filter_message_verdict_DROP)
	{
		io->filter_policy = policy;
	}
}

void
nmsg_io_set_interval(nmsg_io_t io, unsigned interval) {
	io->interval = interval;
}

void
nmsg_io_set_interval_randomized(nmsg_io_t io, bool randomized) {
	io->interval_randomized = randomized;
}

void
nmsg_io_set_output_mode(nmsg_io_t io, nmsg_io_output_mode output_mode) {
	switch (output_mode) {
	case nmsg_io_output_mode_stripe:
	case nmsg_io_output_mode_mirror:
		io->output_mode = output_mode;
	}
}

/* Private functions. */

static void
init_timespec_intervals(nmsg_io_t io) {
	struct nmsg_io_output *io_output;
	struct timespec now;

	nmsg_timespec_get(&now);
	now.tv_nsec = 0;

	if (io->interval_randomized == false) {
		now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);
	} else {
		nmsg_random_t r = nmsg_random_init();
		io->interval_offset = nmsg_random_uniform(r, io->interval);
		now.tv_sec = now.tv_sec - (now.tv_sec % io->interval) + io->interval_offset;
		nmsg_random_destroy(&r);
	}

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

	/* It's possible a set "count" has been reached. */
	check_close_event(iothr, io_output, 1);

	if (io->stop) {
		reset_close_event(iothr, io_output);
		nmsg_message_destroy(&msg);
		return (nmsg_res_stop);
	}

	res = nmsg_output_write(io_output->output, msg);
	if (io_output->output->type != nmsg_output_type_callback)
		nmsg_message_destroy(&msg);

	/*
	 * Reset only after the write, in case another thread invokes
	 * check_close_event and makes changes to io_output in the meantime.
	 */
	reset_close_event(iothr, io_output);

	if (res != nmsg_res_success)
		return (res);

	atomic_fetch_add_explicit(&io->io_count_nmsg_payload_out, 1, memory_order_relaxed);

	return (res);
}

/*
 * If either nmsg_io_set_count() or nmsg_io_set_interval() has been called on
 * this nmsg_io_t, this routine checks whether the count or interval has been
 * satisfied, and then invokes any callback set with nmsg_io_set_close_fp().
 */
static void
check_close_event(struct nmsg_io_thr *iothr, struct nmsg_io_output *io_output, uint64_t count) {
	struct nmsg_io_close_event ce;
	nmsg_io_t io = iothr->io;

	if (io->close_fp != NULL || io->count > 0)
		pthread_mutex_lock(&io_output->lock);

	if (io->close_fp != NULL) {
		while (io_output->closing)
			pthread_cond_wait(&io_output->wait_cond, &io_output->lock);

		io_output->refcount++;
	}

	if (io_output->output == NULL) {
		io->stop = true;
		goto out;
	}

	/* count check */
	if (io->count > 0 && io_output->count_next_close == 0)
		io_output->count_next_close = io->count;

	if (io->count > 0 &&
	    io_output->count_nmsg_payload_out == io_output->count_next_close)
	{
		if (io->close_fp != NULL) {
			/* close notification is enabled */
			ce.io = io;
			ce.user = io_output->user;
			ce.output = &io_output->output;

			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_count;
			ce.output_type = io_output->output->type;

			call_close_fp(iothr, io_output, &ce);

			io_output->count_next_close += io->count;

			if (io_output->output == NULL) {
				io->stop = true;
				goto out;
			}
		} else {
			io->stop = true;
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
			now.tv_sec = now.tv_sec - (now.tv_sec % io->interval) + io->interval_offset;
			io_output->last = now;

			ce.io = io;
			ce.user = io_output->user;
			ce.output = &io_output->output;

			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_interval;
			ce.output_type = io_output->output->type;

			call_close_fp(iothr, io_output, &ce);

			if (io_output->output == NULL) {
				io->stop = true;
				goto out;
			}
		} else {
			io->stop = true;
			goto out;
		}
	}

out:
	/*
	 * This incr is implicitly locked IF it's used, and this counter is
	 * only used IF io->count > 0; that condition results in an acquired
	 * lock at the beginning of this function.
	 */
	io_output->count_nmsg_payload_out += count;

	if (io->close_fp != NULL || io->count > 0)
		pthread_mutex_unlock(&io_output->lock);
}

static void
call_close_fp(struct nmsg_io_thr *iothr, struct nmsg_io_output *io_output, struct nmsg_io_close_event *ce) {
	nmsg_io_t io = iothr->io;

	io_output->closing = true;

	/*
	 * Multiple callers to check_close_event() can increment refcount, but
	 * only one of these may call the close_fp() callback at any given time.
	 *
	 * No more than one thread will ever wait in this conditional since it
	 * has set already closing = true under lock above, and any competing
	 * thread will stall in check_close_event() waiting for !closing until
	 * the prolog of this function.
	 */
	if (io_output->refcount > 1) {
		io_output->refcount--;
		pthread_cond_wait(&io_output->close_cond, &io_output->lock);
		io_output->refcount++;
	}

	io->close_fp(ce);
	io_output->closing = false;
	pthread_cond_broadcast(&io_output->wait_cond);
}

static void
reset_close_event(struct nmsg_io_thr *iothr, struct nmsg_io_output *io_output) {
	nmsg_io_t io = iothr->io;

	if (io->close_fp != NULL) {
		pthread_mutex_lock(&io_output->lock);
		/* Any thread waiting on close_cond MUST have closing set. */
		if (--io_output->refcount == 0 && io_output->closing) {
			pthread_cond_signal(&io_output->close_cond);
		}
		pthread_mutex_unlock(&io_output->lock);
	}
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

static nmsg_res
io_run_filters(nmsg_io_t io,
	       nmsg_io_filter_vec *filters,
	       nmsg_message_t *msg,
	       nmsg_filter_message_verdict *vres)
{
	nmsg_filter_message_verdict verdict;
	*vres = io->filter_policy;
	for (size_t i = 0; i < nmsg_io_filter_vec_size(filters); i++) {
		struct nmsg_io_filter *filter = nmsg_io_filter_vec_value(filters, i);
		nmsg_res res = nmsg_res_failure;

		switch (filter->type) {
		case nmsg_io_filter_type_function:
			res = filter->fp(msg, filter->data, &verdict);
			break;
		case nmsg_io_filter_type_module:
			res = nmsg_fltmod_filter_message(filter->mod, msg, filter->data, &verdict);
			break;
		}

		if (res != nmsg_res_success)
			return res;

		switch (verdict) {
		case nmsg_filter_message_verdict_DECLINED:
			continue;
		case nmsg_filter_message_verdict_ACCEPT:
			*vres = verdict;
			return nmsg_res_success;
		case nmsg_filter_message_verdict_DROP:
			*vres = verdict;
			return nmsg_res_success;
		}

	}
	return nmsg_res_success;
}

static void *
io_thr_input(void *user) {
	nmsg_filter_message_verdict vres;
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

	_nmsg_dprintfv(io->debug, 4, "nmsg_io: started input thread @ %p\n", (void *)iothr);

	/* sanity checks */
	if (io_output == NULL) {
		_nmsg_dprintfv(io->debug, 1, "%s", "nmsg_io: no outputs\n");
		iothr->res = nmsg_res_failure;
		return (NULL);
	}

	/* call user function */
	if (io->atstart_fp != NULL)
		io->atstart_fp(iothr->threadno, io->atstart_user);

	/* Setup thread-local filter chain. */
	if (nmsg_io_filter_vec_size(io->filters) > 0) {
		/* Allocate thread-local filter vector. */
		iothr->filters = nmsg_io_filter_vec_init(nmsg_io_filter_vec_size(io->filters));

		/**
		 * Copy the io-wide filter vector into the thread-local filter
		 * vector. For module filters, call nmsg_fltmod_thread_init().
		 */
		for (size_t i = 0; i < nmsg_io_filter_vec_size(io->filters); i++) {
			struct nmsg_io_filter *filter = nmsg_io_filter_vec_value(io->filters, i);

			/* Make a thread-local copy. */
			struct nmsg_io_filter *thr_filter = my_calloc(1, sizeof(*thr_filter));
			memcpy(thr_filter, filter, sizeof(*thr_filter));

			/* Initialize thread-local data. */
			if (thr_filter->type == nmsg_io_filter_type_module) {
				res = nmsg_fltmod_thread_init(thr_filter->mod, &thr_filter->data);
				if (res != nmsg_res_success) {
					my_free(thr_filter);
					_nmsg_dprintfv(io->debug, 1, "%s",
						"nmsg_iothr: failed to initialize filter module\n");
					iothr->res = res;
					return (NULL);
				}
			}

			/* Append to the thread-local filter vector. */
			nmsg_io_filter_vec_add(iothr->filters, thr_filter);
		}
	}

	/* loop over input */
	while (!io->stop) {
		nmsg_timespec_get(&iothr->now);
		res = nmsg_input_read(io_input->input, &msg);

		if (io->stop) {
			if (res == nmsg_res_success && msg != NULL)
				nmsg_message_destroy(&msg);
			break;
		}
		if (res == nmsg_res_again) {
			/* It's possible a set interval has elapsed. */
			check_close_event(iothr, io_output, 0);
			reset_close_event(iothr, io_output);
			continue;
		}
		if (res != nmsg_res_success) {
			iothr->res = res;
			break;
		}

		assert(msg != NULL);

		io_input->count_nmsg_payload_in += 1;

		if (iothr->filters != NULL) {
			res = io_run_filters(io, iothr->filters, &msg, &vres);
			if (res != nmsg_res_success) {
				nmsg_message_destroy(&msg);
				iothr->res = res;
				break;
			}

			if (vres == nmsg_filter_message_verdict_DROP) {
				nmsg_message_destroy(&msg);
				continue;
			}
		}

		if (io->output_mode == nmsg_io_output_mode_stripe)
			res = io_write(iothr, io_output, msg);
		else if (io->output_mode == nmsg_io_output_mode_mirror)
			res = io_write_mirrored(iothr, msg);

		if (res != nmsg_res_success) {
			iothr->res = res;
			break;
		}
		io_output = ISC_LIST_NEXT(io_output, link);
		if (io_output == NULL)
			io_output = ISC_LIST_HEAD(io->io_outputs);
	}

	/* Clean up thread-local filters. */
	if (iothr->filters != NULL) {
		/* Iterate over each filter. */
		for (size_t i = 0; i < nmsg_io_filter_vec_size(iothr->filters); i++) {
			struct nmsg_io_filter *filter = nmsg_io_filter_vec_value(iothr->filters, i);

			/* Free any resources associated with the filter. */
			if (filter->type == nmsg_io_filter_type_module) {
				res = nmsg_fltmod_thread_fini(filter->mod, filter->data);
				if (res != nmsg_res_success) {
					_nmsg_dprintfv(io->debug, 4,
						"nmsg_iothr: filter module @ %p finalizer failed: "
						"%s (%d)\n",
						(void *)filter->mod, nmsg_res_lookup(res), res);
				}
			}
			my_free(filter);
		}

		/* Delete the filter vector. */
		nmsg_io_filter_vec_destroy(&iothr->filters);
	}

	/* call user function */
	if (io->atexit_fp != NULL)
		io->atexit_fp(iothr->threadno, io->atexit_user);

	_nmsg_dprintfv(io->debug, 2,
		       "nmsg_io: iothr=%p count_nmsg_payload_in=%" PRIu64 "\n",
		       (void *)iothr, io_input->count_nmsg_payload_in);
	return (NULL);
}
