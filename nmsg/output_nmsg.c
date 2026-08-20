/*
 * Copyright (c) 2023-2024 DomainTools LLC
 * Copyright (c) 2008-2019 by Farsight Security, Inc.
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

/* Forward. */
static nmsg_res container_write(nmsg_output_t, nmsg_container_t*);
static nmsg_res container_submit(nmsg_output_t, nmsg_container_t *, bool, uint64_t);
static nmsg_res frag_write(nmsg_output_t, nmsg_container_t);
static nmsg_res send_buffer(nmsg_output_t, uint8_t *buf, size_t len);
static nmsg_res async_drain(struct nmsg_ostr_async *);

/* Data structures. */

/*
 * A compressor pool: a ring of slots, nworkers compressor threads and one
 * committer thread.
 *
 * A container is given a ticket when it is sealed, under c_lock, so tickets
 * follow the order the containers were closed in. Slot i serves every ticket
 * with (ticket % depth) == i, so the producer of ticket T waits only for
 * ticket T - depth to have been written.
 *
 * Compression runs on whichever thread is free. Only the committer writes, and
 * only in ticket order, so the byte stream is identical to the synchronous
 * path however many workers are running.
 *
 * A producer that finds every worker busy compresses the container itself
 * rather than waiting. That is exactly what the synchronous path does, so the
 * pool is never slower than no pool at all.
 */
typedef enum {
	slot_empty = 0,	/* Free. */
	slot_work,	/* Container waiting for a compressor. */
	slot_taken,	/* A worker or a producer is compressing it. */
	slot_done,	/* Compressed, waiting its turn to be written. */
	slot_frag	/* Oversized: the committer must fragment it itself. */
} async_slot_state;

struct async_slot {
	async_slot_state	state;
	nmsg_container_t	co;		/* slot_work, slot_frag */
	uint8_t			*buf;		/* slot_done */
	size_t			buf_len;
	nmsg_res		res;
};

struct nmsg_ostr_async {
	pthread_mutex_t		lock;
	pthread_cond_t		work_ready;	/* A slot became slot_work. */
	pthread_cond_t		commit_ready;	/* The committer's slot is ready. */
	pthread_cond_t		slot_free;	/* A slot became slot_empty. */
	struct async_slot	*slots;
	unsigned		depth;
	unsigned		nworkers;
	unsigned		busy;		/* Workers currently compressing. */
	uint64_t		issued;		/* Highest ticket claimed, plus one. */
	uint64_t		commit_next;	/* Ticket allowed to write now. */
	bool			shutdown;
	bool			started;
	bool			failed;		/* Thread creation failed; stay inline. */
	pthread_t		*workers;
	pthread_t		committer;
	nmsg_res		first_error;	/* Sticky; surfaced by flush. */
	nmsg_output_t		output;
	uint64_t		n_inline;	/* Containers a producer compressed. */
	uint64_t		n_waited;	/* Producers that waited for a slot. */
};

/* Internal functions. */

nmsg_res
_output_nmsg_async_init(nmsg_output_t output, unsigned nworkers) {
	struct nmsg_ostr_async *pool;
	unsigned depth;

	if (nworkers == 0)
		return (nmsg_res_success);

	if (output->stream->so_pool != NULL)
		return (nmsg_res_success);

	/*
	 * One slot per worker to compress in, plus a fixed margin for
	 * producers to deposit into and for finished buffers waiting their
	 * turn to be written. The margin does not need to scale with the
	 * worker count: a producer that cannot get a slot compresses the
	 * container itself rather than waiting, so a tight ring costs a little
	 * of the parallelism and never blocks a reader.
	 *
	 * A slot holds a container's payloads in memory, which is not the
	 * 1 MiB serialized size -- a channel of 30-byte payloads puts ~37k of
	 * them in a container, over 5 MB. That is what bounds the ring, and
	 * why the automatic worker count is capped.
	 */
	depth = nworkers + 8;

	pool = calloc(1, sizeof(*pool));
	if (pool == NULL)
		return (nmsg_res_memfail);

	pool->slots = calloc(depth, sizeof(*pool->slots));
	if (pool->slots == NULL)
		goto fail_slots;

	pool->workers = calloc(nworkers, sizeof(*pool->workers));
	if (pool->workers == NULL)
		goto fail_workers;

	if (pthread_mutex_init(&pool->lock, NULL) != 0)
		goto fail_mutex;
	if (pthread_cond_init(&pool->work_ready, NULL) != 0)
		goto fail_work_ready;
	if (pthread_cond_init(&pool->commit_ready, NULL) != 0)
		goto fail_commit_ready;
	if (pthread_cond_init(&pool->slot_free, NULL) != 0)
		goto fail_slot_free;

	pool->depth = depth;
	pool->nworkers = nworkers;
	pool->output = output;
	output->stream->so_pool = pool;

	return (nmsg_res_success);

fail_slot_free:
	pthread_cond_destroy(&pool->commit_ready);
fail_commit_ready:
	pthread_cond_destroy(&pool->work_ready);
fail_work_ready:
	pthread_mutex_destroy(&pool->lock);
fail_mutex:
	free(pool->workers);
fail_workers:
	free(pool->slots);
fail_slots:
	free(pool);

	return (nmsg_res_failure);
}

/*
 * Stop the pool and reclaim it. Everything still queued is written first.
 * Must run before the stream's fd, random and locks go away, since the threads
 * use all of them.
 */
nmsg_res
_output_nmsg_async_destroy(nmsg_output_t output) {
	struct nmsg_ostr_async *pool = output->stream->so_pool;
	nmsg_res res;
	bool started;
	unsigned i;

	if (pool == NULL)
		return (nmsg_res_success);

	pthread_mutex_lock(&pool->lock);
	pool->shutdown = true;		/* Set under the lock: a thread about */
	started = pool->started;	/* to wait would miss the wakeup. */
	pthread_cond_broadcast(&pool->work_ready);
	pthread_cond_broadcast(&pool->commit_ready);
	pthread_cond_broadcast(&pool->slot_free);
	pthread_mutex_unlock(&pool->lock);

	if (started) {
		for (i = 0; i < pool->nworkers; i++)
			pthread_join(pool->workers[i], NULL);
		pthread_join(pool->committer, NULL);
	}

	if (pool->n_inline > 0 || pool->n_waited > 0)
		_nmsg_dprintf(2, "%s: %u worker(s); %" PRIu64 " container(s) "
			      "compressed by the reader, %" PRIu64 " wait(s) for "
			      "a free slot\n", __func__, pool->nworkers,
			      pool->n_inline, pool->n_waited);

	/* Read after the joins; the threads write it until they exit. */
	res = pool->first_error;

	pthread_cond_destroy(&pool->slot_free);
	pthread_cond_destroy(&pool->commit_ready);
	pthread_cond_destroy(&pool->work_ready);
	pthread_mutex_destroy(&pool->lock);
	free(pool->workers);
	free(pool->slots);
	free(pool);
	output->stream->so_pool = NULL;

	return (res);
}

nmsg_res
_output_nmsg_flush(nmsg_output_t output) {
	struct nmsg_stream_output *ostr = output->stream;
	nmsg_res res = nmsg_res_success;
	nmsg_res drain_res;
	nmsg_container_t old_c = NULL;
	uint64_t ticket = 0;

	pthread_mutex_lock(&ostr->c_lock);

	if (nmsg_container_get_num_payloads(ostr->c) > 0) {
		old_c = ostr->c;
		ticket = ostr->so_ticket++;

		ostr->c = nmsg_container_init(ostr->bufsz);
		if (ostr->c == NULL)
			res = nmsg_res_memfail;
		else
			nmsg_container_set_sequence(ostr->c, ostr->do_sequence);
	}

	pthread_mutex_unlock(&ostr->c_lock);

	/*
	 * Submitted outside c_lock. Flush runs on every file rotation, and a
	 * submit can wait for a free slot; doing that under c_lock would hold
	 * off every reader thread for the length of a compression.
	 */
	if (old_c != NULL) {
		nmsg_res sub_res;

		sub_res = container_submit(output, &old_c, false, ticket);
		if (res == nmsg_res_success)
			res = sub_res;
	}

	/*
	 * A flush means the data has been written, so wait out anything the
	 * pool is still holding.
	 */
	drain_res = async_drain(ostr->so_pool);
	if (res == nmsg_res_success)
		res = drain_res;

	return (res);
}

nmsg_res
_output_nmsg_write(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	struct nmsg_stream_output *ostr = output->stream;
	nmsg_container_t old_c, new_c;
	nmsg_res res;
	uint64_t ticket = 0;
	bool must_flush, is_buffered;

	assert(msg->np != NULL);
	np = msg->np;

	/* set source, output, group if necessary */
	if (ostr->source != 0) {
		np->source = ostr->source;
		np->has_source = 1;
	}
	if (ostr->operator != 0) {
		np->operator_ = ostr->operator;
		np->has_operator_ = 1;
	}
	if (ostr->group != 0) {
		np->group = ostr->group;
		np->has_group = 1;
	}

retry:
	must_flush = false;
	old_c = new_c = NULL;

	pthread_mutex_lock(&ostr->c_lock);	/* Lock for add to container. */

	/*
	 * Try to add the message to the current container. If the current
	 * container needs further processing (i.e. write/send its contents),
	 * then the current thread will:
	 *   1) Set up a new container for the stream.
	 *   2) Release container lock so other threads can use new container.
	 *   3) Proceed to further process the current container.
	 */
	res = nmsg_container_add(ostr->c, msg);

	/*
	 * If the processing block below is entered, first set up a new
	 * container for the other threads to use.
	 */
	is_buffered = ostr->buffered;	/* Save this value. */
	if ((res == nmsg_res_container_full) ||
	    (res == nmsg_res_success && is_buffered == false) ||
	    (res == nmsg_res_container_overfull)) {
		must_flush = true;	/* Will flush container below. */

		/* Create replacement container. */
		new_c = nmsg_container_init(ostr->bufsz);
		if (new_c == NULL) {
			pthread_mutex_unlock(&ostr->c_lock);
			return (nmsg_res_memfail);
		}

		nmsg_container_set_sequence(new_c, ostr->do_sequence);

		old_c = ostr->c;	/* Process old, proceed with new. */
		ostr->c = new_c;

		/*
		 * Ticket taken here, under c_lock, because this is where the
		 * container's contents become final. Taking it in
		 * container_submit() would order the containers by which
		 * thread won the race after the unlock, which is not the
		 * order they were filled in.
		 */
		ticket = ostr->so_ticket++;
	}

	pthread_mutex_unlock(&ostr->c_lock);	/* Release locked container to other threads. */

	if (!must_flush)			/* Nothing more to do here. */
		return (res);

	/* Reaching here WILL flush the prior container. */
	if (res == nmsg_res_container_full) {		/* Doesn't include current message. */
		res = container_submit(output, &old_c, false, ticket);	/* Write data from prior container. */
		if (res != nmsg_res_success)
			return (res);

		/* Proceed to write current message to new container. */
		goto retry;
	} else if (res == nmsg_res_success && is_buffered == false) {	/* Includes current message. */
		res = container_submit(output, &old_c, false, ticket);
	} else if (res == nmsg_res_container_overfull) {		/* Includes current message. */
		res = container_submit(output, &old_c, true, ticket);
	}

	return (res);
}

/* Private functions. */

/*
 * Compress one container into a standalone buffer. The container is destroyed
 * either way, as container_write() does.
 */
static nmsg_res
container_compress(nmsg_output_t output, nmsg_container_t *co,
		   uint8_t **buf, size_t *buf_len)
{
	struct nmsg_stream_output *ostr = output->stream;
	nmsg_res res;
	uint32_t seq;
	uint8_t *shrunk;

	/* Multiple threads can enter here at once. */
	seq = atomic_fetch_add_explicit(&ostr->so_sequence_num, 1, memory_order_relaxed);

	res = nmsg_container_serialize(*co, buf, buf_len, true, /* do_header */
				       ostr->do_zlib, seq, ostr->sequence_id);
	nmsg_container_destroy(co);

	if (res != nmsg_res_success) {
		*buf = NULL;
		*buf_len = 0;
		return (res);
	}

	/*
	 * nmsg_container_serialize() returns the base of an allocation sized
	 * for the worst case, twice the unpacked estimate. A slot holds that
	 * until every earlier ticket has been written, so hand the rest back.
	 */
	shrunk = realloc(*buf, *buf_len);
	if (shrunk != NULL)
		*buf = shrunk;

	return (res);
}

/*
 * Send/write the contents of a container.
 * Container is destroyed, whether contents are successfully processed or not.
 */
static nmsg_res
container_write(nmsg_output_t output, nmsg_container_t *co)
{
	nmsg_res res;
	size_t buf_len;
	uint8_t *buf;

	res = container_compress(output, co, &buf, &buf_len);
	if (res != nmsg_res_success)
		return (res);

	return (send_buffer(output, buf, buf_len));
}

/* Note an error, keeping the first one seen. Caller holds pool->lock. */
static void
async_record_error(struct nmsg_ostr_async *pool, nmsg_res res)
{
	if (res != nmsg_res_success && pool->first_error == nmsg_res_success)
		pool->first_error = res;
}

/*
 * Compressor thread. Takes any slot that needs compressing, in whatever order
 * they become ready: compression order does not matter, only write order does,
 * and the committer enforces that.
 */
static void *
async_worker(void *arg)
{
	struct nmsg_ostr_async *pool = (struct nmsg_ostr_async *) arg;

	pthread_mutex_lock(&pool->lock);

	for (;;) {
		struct async_slot *slot = NULL;
		nmsg_container_t co;
		uint8_t *buf;
		size_t buf_len;
		nmsg_res res;
		unsigned i;

		for (i = 0; i < pool->depth; i++) {
			if (pool->slots[i].state == slot_work) {
				slot = &pool->slots[i];
				break;
			}
		}

		if (slot == NULL) {
			/*
			 * Nothing to compress. Exit only once the producers
			 * have stopped, so a container queued just before
			 * shutdown is still compressed and written; that
			 * happens on every clean SIGTERM.
			 */
			if (pool->shutdown)
				break;
			pthread_cond_wait(&pool->work_ready, &pool->lock);
			continue;
		}

		slot->state = slot_taken;
		co = slot->co;
		slot->co = NULL;
		pool->busy++;
		pthread_mutex_unlock(&pool->lock);

		res = container_compress(pool->output, &co, &buf, &buf_len);

		pthread_mutex_lock(&pool->lock);
		pool->busy--;
		slot->buf = buf;
		slot->buf_len = buf_len;
		slot->res = res;
		slot->state = slot_done;
		pthread_cond_broadcast(&pool->commit_ready);
	}

	pthread_mutex_unlock(&pool->lock);

	return (NULL);
}

/*
 * The only thread that writes. It takes tickets strictly in order, so the file
 * is byte-identical to what the synchronous path would have produced no matter
 * how many workers compressed in parallel.
 *
 * It is also the only caller of frag_write().
 */
static void *
async_committer(void *arg)
{
	struct nmsg_ostr_async *pool = (struct nmsg_ostr_async *) arg;

	pthread_mutex_lock(&pool->lock);

	for (;;) {
		struct async_slot *slot = &pool->slots[pool->commit_next % pool->depth];
		async_slot_state state = slot->state;
		nmsg_res res;

		if (state == slot_done) {
			uint8_t *buf = slot->buf;
			size_t buf_len = slot->buf_len;

			res = slot->res;
			slot->buf = NULL;
			pthread_mutex_unlock(&pool->lock);

			/* send_buffer() owns buf from here, error or not. */
			if (res == nmsg_res_success)
				res = send_buffer(pool->output, buf, buf_len);

			pthread_mutex_lock(&pool->lock);
		} else if (state == slot_frag) {
			nmsg_container_t co = slot->co;

			slot->co = NULL;
			pthread_mutex_unlock(&pool->lock);

			/* frag_write() takes the container by value and destroys it. */
			res = frag_write(pool->output, co);

			pthread_mutex_lock(&pool->lock);
		} else {
			/*
			 * The next ticket is not ready. Exit only when the
			 * producers have stopped and every ticket they issued
			 * has been written.
			 */
			if (pool->shutdown && pool->commit_next >= pool->issued)
				break;
			pthread_cond_wait(&pool->commit_ready, &pool->lock);
			continue;
		}

		async_record_error(pool, res);
		slot->state = slot_empty;
		pool->commit_next++;
		pthread_cond_broadcast(&pool->slot_free);
	}

	pthread_mutex_unlock(&pool->lock);

	return (NULL);
}

/*
 * Start the threads. Called under pool->lock on first submit rather than when
 * the output is configured, because nmsgtool creates its outputs before it
 * daemonizes, and daemonize() is a bare fork() which no thread survives.
 * Starting on first write puts the threads in whichever process does the
 * writing.
 */
static void
async_start(struct nmsg_ostr_async *pool)
{
	unsigned i;
	int pthread_res;

	for (i = 0; i < pool->nworkers; i++) {
		pthread_res = pthread_create(&pool->workers[i], NULL, async_worker, pool);
		if (pthread_res != 0)
			goto fail;
	}

	pthread_res = pthread_create(&pool->committer, NULL, async_committer, pool);
	if (pthread_res != 0)
		goto fail;

	pool->started = true;
	return;

fail:
	/*
	 * Stop whatever did start and fall back to compressing inline. Joining
	 * needs the lock released, and the caller still holds a container, so
	 * this stays simple: the threads created so far see shutdown and exit,
	 * and destroy joins them.
	 */
	pool->nworkers = i;
	pool->failed = true;
	pool->shutdown = true;
	pool->started = (i > 0);
	pthread_cond_broadcast(&pool->work_ready);
	pthread_cond_broadcast(&pool->commit_ready);
	_nmsg_dprintf(1, "%s: pthread_create() failed: %s\n", __func__,
		      strerror(pthread_res));
}

/*
 * Wait until every ticket issued so far has been written, and take any error
 * the pool recorded. Under nmsg_io this cannot starve: check_close_event()
 * holds io_output->refcount across the write and call_close_fp() waits for it
 * to drop, so no other thread is inside nmsg_output_write() while a close runs.
 * A caller driving nmsg_output_flush() directly from several threads has no
 * such guarantee.
 */
static nmsg_res
async_drain(struct nmsg_ostr_async *pool)
{
	nmsg_res res;

	if (pool == NULL)
		return (nmsg_res_success);

	pthread_mutex_lock(&pool->lock);
	while (pool->started && !pool->failed && pool->commit_next < pool->issued)
		pthread_cond_wait(&pool->slot_free, &pool->lock);
	res = pool->first_error;
	pool->first_error = nmsg_res_success;
	pthread_mutex_unlock(&pool->lock);

	return (res);
}

/*
 * Hand a finished container to the pool, or process it inline if there is no
 * pool. The container is consumed either way.
 *
 * The pool reports success for the container it just took, since that
 * container has not been written yet. An error from an EARLIER container is
 * returned here.
 */
static nmsg_res
container_submit(nmsg_output_t output, nmsg_container_t *co, bool is_frag,
		 uint64_t ticket)
{
	struct nmsg_ostr_async *pool = output->stream->so_pool;
	struct async_slot *slot;
	nmsg_res res = nmsg_res_success;
	uint8_t *buf;
	size_t buf_len;
	bool inline_compress = false;

	if (pool == NULL)
		goto inline_path;

	pthread_mutex_lock(&pool->lock);

	if (!pool->started && !pool->failed && !pool->shutdown)
		async_start(pool);

	if (!pool->started || pool->failed || pool->shutdown) {
		pthread_mutex_unlock(&pool->lock);
		goto inline_path;
	}

	slot = &pool->slots[ticket % pool->depth];

	/*
	 * Wait for the slot this ticket owns, which the ticket 'depth' earlier
	 * releases when it is written. Only reached when the writer has fallen
	 * a whole ring behind.
	 */
	if (slot->state != slot_empty) {
		pool->n_waited++;
		while (slot->state != slot_empty && !pool->shutdown)
			pthread_cond_wait(&pool->slot_free, &pool->lock);

		if (pool->shutdown) {
			pthread_mutex_unlock(&pool->lock);
			goto inline_path;
		}
	}

	if (ticket >= pool->issued)
		pool->issued = ticket + 1;

	if (is_frag) {
		/* Only the committer fragments; see async_committer(). */
		slot->co = *co;
		*co = NULL;
		slot->state = slot_frag;
		pthread_cond_broadcast(&pool->commit_ready);
	} else if (pool->busy < pool->nworkers) {
		/* A worker is free: hand it over and get back to reading. */
		slot->co = *co;
		*co = NULL;
		slot->state = slot_work;
		pthread_cond_signal(&pool->work_ready);
	} else {
		/*
		 * Every worker is busy. Compress it here rather than wait then deposit
		 * the result and return.
		 */
		slot->state = slot_taken;
		pool->n_inline++;
		inline_compress = true;
	}

	res = pool->first_error;
	pool->first_error = nmsg_res_success;
	pthread_mutex_unlock(&pool->lock);

	if (inline_compress) {
		nmsg_res c_res = container_compress(output, co, &buf, &buf_len);

		pthread_mutex_lock(&pool->lock);
		slot->buf = buf;
		slot->buf_len = buf_len;
		slot->res = c_res;
		slot->state = slot_done;
		pthread_cond_broadcast(&pool->commit_ready);
		pthread_mutex_unlock(&pool->lock);
	}

	return (res);

inline_path:
	if (is_frag) {
		nmsg_container_t tmp = *co;

		/*
		 * frag_write() takes the container by value and destroys it
		 * internally, unlike container_write().
		 */
		*co = NULL;
		return (frag_write(output, tmp));
	}

	return (container_write(output, co));
}

static nmsg_res
write_sock(int fd, uint8_t *buf, size_t len)
{
	ssize_t bytes_written;

	bytes_written = write(fd, buf, len);
	if (bytes_written < 0) {
		_nmsg_dprintf(1, "%s: write() failed: %s\n", __func__, strerror(errno));
		free(buf);
		return (nmsg_res_errno);
	}
	free(buf);
	assert((size_t) bytes_written == len);
	return (nmsg_res_success);
}

#ifdef HAVE_LIBZMQ
static void
free_wrapper(void *ptr, void *hint __attribute__((unused)))
{
	free(ptr);
}

static nmsg_res
write_zmq(nmsg_output_t output, uint8_t *buf, size_t len)
{
	nmsg_res res = nmsg_res_success;
	zmq_msg_t zmsg;

	if (zmq_msg_init_data(&zmsg, buf, len, free_wrapper, NULL)) {
		free(buf);
		return (nmsg_res_failure);
	}

	for (;;) {
		int ret;
		zmq_pollitem_t zitems[1];
		zitems[0].socket = output->stream->zmq;
		zitems[0].events = ZMQ_POLLOUT;
		ret = zmq_poll(zitems, 1, NMSG_RBUF_TIMEOUT);
		if (ret > 0) {
			ret = zmq_sendmsg(output->stream->zmq, &zmsg, 0);
			if (ret > 0) {
				break;
			} else {
				res = nmsg_res_failure;
				_nmsg_dprintf(1, "%s: zmq_sendmsg() failed: %s\n",
					      __func__, strerror(errno));
				break;
			}
		}
		if (output->stop) {
			res = nmsg_res_stop;
			break;
		}
	}

	zmq_msg_close(&zmsg);
	return (res);
}
#endif /* HAVE_LIBZMQ */

static nmsg_res
write_file(int fd, uint8_t *buf, size_t len)
{
	ssize_t bytes_written;
	const uint8_t *ptr = buf;

	while (len) {
		bytes_written = write(fd, ptr, len);
		if (bytes_written < 0 && errno == EINTR)
			continue;
		if (bytes_written < 0) {
			_nmsg_dprintf(1, "%s: write() failed: %s\n", __func__, strerror(errno));
			free(buf);
			return (nmsg_res_errno);
		}
		ptr += bytes_written;
		len -= bytes_written;
	}
	free(buf);
	return (nmsg_res_success);
}

/*
 * Send a buffer holding a serialized container to its destination.
 * The buffer will ALWAYS be free'd before this function returns.
 *
 * Returns status of send.
 */
static nmsg_res
send_buffer(nmsg_output_t output, uint8_t *buf, size_t len)
{
	struct nmsg_stream_output *ostr = output->stream;
	nmsg_res res;

	pthread_mutex_lock(&ostr->w_lock);

	if (ostr->type == nmsg_stream_type_sock) {
		res = write_sock(ostr->fd, buf, len);
	} else if (ostr->type == nmsg_stream_type_file) {
		res = write_file(ostr->fd, buf, len);
	} else if (ostr->type == nmsg_stream_type_zmq) {
#ifdef HAVE_LIBZMQ
		res = write_zmq(output, buf, len);
#else /* HAVE_LIBZMQ */
		assert(ostr->type != nmsg_stream_type_zmq);
#endif /* HAVE_LIBZMQ */
	} else if (ostr->type == nmsg_stream_type_kafka) {
#ifdef HAVE_LIBRDKAFKA
		res = kafka_write(output->stream->kafka, NULL, 0, buf, len);
#else /* HAVE_LIBRDKAFKA */
		assert(ostr->type != nmsg_stream_type_kafka);
#endif /* HAVE_LIBRDKAFKA */
	} else {
		assert(0);
	}

	/* Do "rate limit" delay (under lock). */
	if (ostr->rate != NULL)
		nmsg_rate_sleep(ostr->rate);

	pthread_mutex_unlock(&ostr->w_lock);

	return (res);
}

#ifdef HAVE_LIBRDKAFKA
nmsg_res
_output_kafka_payload_write(nmsg_output_t output, nmsg_message_t msg) {
	nmsg_res res;
	struct nmsg_strbuf_storage key_sbs;
	struct nmsg_strbuf *key_sb = NULL;
	uint8_t *buf = NULL, *key = NULL;
	size_t buf_len, key_len = 0;

	assert(msg->np != NULL);

	buf_len = nmsg__nmsg_payload__get_packed_size(msg->np);
	buf = malloc(buf_len);
	if (buf == NULL)
		return nmsg_res_memfail;
	nmsg__nmsg_payload__pack(msg->np, buf);

	if (output->kafka->key_field != NULL) {
		key_sb = _nmsg_strbuf_init(&key_sbs);
		res = _nmsg_message_get_field_value_as_key(msg, output->kafka->key_field, key_sb);
		if (res != nmsg_res_success)
			goto out;

		key_len = nmsg_strbuf_len(key_sb);
		key = (uint8_t *) key_sb->data;
	}

	/* kafka_write() takes ownership of buf */
	res = kafka_write(output->kafka->ctx, key, key_len, buf, buf_len);
	buf = NULL;

out:
	if (buf != NULL)
		free(buf);
	if (key_sb != NULL)
		_nmsg_strbuf_destroy(&key_sbs);
	return res;
}

nmsg_res
_output_kafka_payload_flush(nmsg_output_t output) {
	kafka_flush(output->kafka->ctx);
	return nmsg_res_success;
}
#endif /* HAVE_LIBRDKAFKA */

static void
header_serialize(uint8_t *buf, uint8_t flags, uint32_t len)
{
	static const char magic[] = NMSG_MAGIC;
	uint16_t version;

	memcpy(buf, magic, sizeof(magic));
	buf += sizeof(magic);

	version = NMSG_PROTOCOL_VERSION | (flags << 8);
	store_net16(buf, version);

	buf += sizeof(version);
	store_net32(buf, len);
}

static nmsg_res
frag_write(nmsg_output_t output, nmsg_container_t co)
{
	Nmsg__NmsgFragment nf;
	struct nmsg_stream_output *ostr = output->stream;
	unsigned i;
	nmsg_res res;
	size_t len, fragpos, fragsz, fraglen, max_fragsz;
	uint32_t seq;
	uint8_t flags = 0, *packed, *frag_packed, *frag_packed_container;

	assert(output->type == nmsg_output_type_stream);

#ifdef HAVE_LIBZMQ
	if (ostr->type == nmsg_stream_type_zmq) {
		/* let ZMQ do fragmentation instead */
		return (container_write(output, &co));
	}
#else /* HAVE_LIBZMQ */
	assert(ostr->type != nmsg_stream_type_zmq);
#endif /* HAVE_LIBZMQ */

	max_fragsz = ostr->bufsz - 32;

	/* Multiple threads can enter here at once. */
	seq = atomic_fetch_add_explicit(&ostr->so_sequence_num, 1, memory_order_relaxed);

	res = nmsg_container_serialize(co, &packed, &len, false, /* do_header */
				       ostr->do_zlib, seq, ostr->sequence_id);
	if (ostr->do_zlib)
		flags |= NMSG_FLAG_ZLIB;

	if (res != nmsg_res_success)
		return (res);

	if (ostr->do_zlib && len <= max_fragsz) {
		/* write out the unfragmented NMSG container */
		res = send_buffer(output, packed, len);
		goto frag_out;
	}

	/* create and send fragments */
	nmsg__nmsg_fragment__init(&nf);

	flags |= NMSG_FLAG_FRAGMENT;
	nf.id = nmsg_random_uint32(ostr->random);
	nf.last = len / max_fragsz;
	nf.crc = htonl(my_crc32c(packed, len));
	nf.has_crc = true;

	for (fragpos = 0, i = 0; fragpos < len; fragpos += max_fragsz, i++)
	{
		/* allocate a buffer large enough to hold one serialized fragment */
		frag_packed = malloc(NMSG_HDRLSZ_V2 + ostr->bufsz + 32);
		if (frag_packed == NULL) {
			free(packed);
			res = nmsg_res_memfail;
			goto frag_out;
		}
		frag_packed_container = frag_packed + NMSG_HDRLSZ_V2;

		/* serialize the fragment */
		nf.current = i;
		fragsz = (len - fragpos > max_fragsz) ? max_fragsz : (len - fragpos);
		nf.fragment.len = fragsz;
		nf.fragment.data = packed + fragpos;
		fraglen = nmsg__nmsg_fragment__pack(&nf, frag_packed_container);
		header_serialize(frag_packed, flags, fraglen);
		fraglen += NMSG_HDRLSZ_V2;

		/* send the serialized fragment */
		res = send_buffer(output, frag_packed, fraglen);
	}
	free(packed);

frag_out:
	nmsg_container_destroy(&co);

	return (res);
}
