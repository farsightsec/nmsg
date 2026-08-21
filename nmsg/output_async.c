/*
 * Copyright (c) 2026 DomainTools LLC
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

/*
 * The compressor pool for a stream output.
 *
 * Everything here is private to this unit: the ring, its slot states and the
 * threads that walk it. output_nmsg.c hands a sealed container over with
 * _output_async_submit() and gets the bytes written for it, and calls back
 * into that file for the actual compressing and writing.
 */

/* Import. */

#include "private.h"

/* Data structures. */

/*
 * A compressor pool: a ring of slots, up to nworkers compressor threads and
 * one committer thread.
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
 *
 * Workers are spawned on demand rather than up front, so 'nworkers' is a
 * ceiling and not an allocation. Once spawned a worker lives until the pool is destroyed.
 */

/*
 * Ring size, independent of the worker ceiling. A slot itself is tiny; what it
 * costs is the container it points at while a ticket is in flight, so the depth
 * bounds worst-case backlog rather than resident memory. The margin keeps slots
 * available for producers to deposit into while every worker is busy, and
 * capping the ceiling at depth - margin stops the pool having more compressors
 * than places to put their output.
 */
#define ASYNC_RING_DEPTH	32
#define ASYNC_RING_MARGIN	8
#define ASYNC_MAX_WORKERS	(ASYNC_RING_DEPTH - ASYNC_RING_MARGIN)

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
	unsigned		nworkers;	/* Ceiling; workers start on demand. */
	unsigned		nstarted;	/* Workers that exist and must be joined. */
	unsigned		busy;		/* Containers assigned to workers. */
	uint64_t		issued;		/* Highest ticket claimed, plus one. */
	uint64_t		commit_next;	/* Ticket allowed to write now. */
	bool			shutdown;
	bool			started;	/* Committer exists; must be joined. */
	bool			failed;		/* No committer; stay inline. */
	bool			spawn_failed;	/* Worker spawn failed; logged once. */
	pthread_t		*workers;
	pthread_t		committer;
	nmsg_res		first_error;	/* Sticky; surfaced by flush. */
	nmsg_output_t		output;
	uint64_t		n_inline;	/* Containers a producer compressed. */
	uint64_t		n_waited;	/* Producers that waited for a slot. */
};

/*
 * Take a reference to the stream's pool, or return NULL if there is none or it
 * is being torn down. Caller holds c_lock.
 */
struct nmsg_ostr_async *
_output_async_ref(struct nmsg_stream_output *ostr)
{
	if (ostr->so_pool == NULL || ostr->so_pool_closing)
		return (NULL);

	ostr->so_inflight++;

	return (ostr->so_pool);
}

/* Drop a reference taken by _output_async_ref() and wake any waiting teardown. */
void
_output_async_unref(struct nmsg_stream_output *ostr)
{
	pthread_mutex_lock(&ostr->c_lock);
	assert(ostr->so_inflight > 0);
	if (--ostr->so_inflight == 0)
		pthread_cond_broadcast(&ostr->c_drained);
	pthread_mutex_unlock(&ostr->c_lock);
}

nmsg_res
_output_async_init(nmsg_output_t output, unsigned nworkers) {
	struct nmsg_stream_output *ostr = output->stream;
	struct nmsg_ostr_async *pool;
	nmsg_res res, old_res = nmsg_res_success;

	if (nworkers == 0)
		return (nmsg_res_success);

	if (nworkers > ASYNC_MAX_WORKERS)
		nworkers = ASYNC_MAX_WORKERS;

	/*
	 * An existing pool's ceiling cannot be changed in place, since its
	 * worker array and ring are already sized, so a different count means
	 * building a replacement. Do that before tearing the old one down: if
	 * the allocation fails there is still a working pool to keep.
	 */
	if (ostr->so_pool != NULL && ostr->so_pool->nworkers == nworkers)
		return (nmsg_res_success);

	pool = calloc(1, sizeof(*pool));
	if (pool == NULL)
		return (nmsg_res_memfail);

	res = nmsg_res_memfail;

	pool->slots = calloc(ASYNC_RING_DEPTH, sizeof(*pool->slots));
	if (pool->slots == NULL)
		goto fail_slots;

	pool->workers = calloc(nworkers, sizeof(*pool->workers));
	if (pool->workers == NULL)
		goto fail_workers;

	res = nmsg_res_failure;

	if (pthread_mutex_init(&pool->lock, NULL) != 0)
		goto fail_mutex;
	if (pthread_cond_init(&pool->work_ready, NULL) != 0)
		goto fail_work_ready;
	if (pthread_cond_init(&pool->commit_ready, NULL) != 0)
		goto fail_commit_ready;
	if (pthread_cond_init(&pool->slot_free, NULL) != 0)
		goto fail_slot_free;

	pool->depth = ASYNC_RING_DEPTH;
	pool->nworkers = nworkers;
	pool->output = output;

	if (ostr->so_pool != NULL)
		old_res = _output_async_destroy(output);

	pthread_mutex_lock(&ostr->c_lock);

	/*
	 * Tickets count for the life of the stream, not the life of the pool,
	 * so a pool built after the first write must start where the stream has
	 * got to. Seeded under c_lock, and the pool is published in the same
	 * hold, so a ticket either predates the pool and is compressed inline or
	 * belongs to it and is at or above commit_next -- never below, where the
	 * committer would wait for it forever.
	 */
	pool->commit_next = pool->issued = ostr->so_ticket;

	/*
	 * Carry any error the previous pool recorded but had not yet reported,
	 * so replacing a pool does not swallow a failed write.
	 */
	pool->first_error = old_res;

	ostr->so_pool = pool;
	pthread_mutex_unlock(&ostr->c_lock);

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

	/* Whatever pool was already in place is untouched and still running. */
	return (res);
}

/*
 * Stop the pool and reclaim it. Everything still queued is written first.
 * Must run before the stream's fd, random and locks go away, since the threads
 * use all of them.
 */
nmsg_res
_output_async_destroy(nmsg_output_t output) {
	struct nmsg_stream_output *ostr = output->stream;
	struct nmsg_ostr_async *pool = ostr->so_pool;
	nmsg_res res;
	bool started;
	unsigned i, nstarted;

	if (pool == NULL)
		return (nmsg_res_success);

	/*
	 * Stop handing tickets to the pool, then wait for the ones already
	 * handed out to arrive. Both happen under c_lock, which is what orders
	 * them against ticket issuance: once this returns, no producer is still
	 * on its way here holding a ticket the committer will wait for.
	 */
	pthread_mutex_lock(&ostr->c_lock);
	ostr->so_pool_closing = true;
	while (ostr->so_inflight > 0)
		pthread_cond_wait(&ostr->c_drained, &ostr->c_lock);
	pthread_mutex_unlock(&ostr->c_lock);

	pthread_mutex_lock(&pool->lock);
	pool->shutdown = true;		/* Set under the lock: a thread about */
	started = pool->started;	/* to wait would miss the wakeup. */
	nstarted = pool->nstarted;
	pthread_cond_broadcast(&pool->work_ready);
	pthread_cond_broadcast(&pool->commit_ready);
	pthread_cond_broadcast(&pool->slot_free);
	pthread_mutex_unlock(&pool->lock);

	/*
	 * Workers and committer are joined on their own counters.
	 */
	for (i = 0; i < nstarted; i++)
		pthread_join(pool->workers[i], NULL);
	if (started)
		pthread_join(pool->committer, NULL);

	if (pool->n_inline > 0 || pool->n_waited > 0)
		_nmsg_dprintf(2, "%s: %u of %u worker(s) started; %" PRIu64
			      " container(s) compressed by the reader, %" PRIu64
			      " wait(s) for a free slot\n", __func__, nstarted,
			      pool->nworkers, pool->n_inline, pool->n_waited);

	/* Read after the joins; the threads write it until they exit. */
	res = pool->first_error;

	pthread_mutex_lock(&ostr->c_lock);
	ostr->so_pool = NULL;
	ostr->so_pool_closing = false;
	pthread_mutex_unlock(&ostr->c_lock);

	pthread_cond_destroy(&pool->slot_free);
	pthread_cond_destroy(&pool->commit_ready);
	pthread_cond_destroy(&pool->work_ready);
	pthread_mutex_destroy(&pool->lock);
	free(pool->workers);
	free(pool->slots);
	free(pool);

	return (res);
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
		pthread_mutex_unlock(&pool->lock);

		res = _output_nmsg_container_compress(pool->output, &co, &buf, &buf_len);

		pthread_mutex_lock(&pool->lock);
		pool->busy--;		/* Counted at deposit; see container_submit(). */
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
 * It is also the only caller of _output_nmsg_frag_write().
 */
static void *
async_committer(void *arg)
{
	struct nmsg_ostr_async *pool = (struct nmsg_ostr_async *) arg;

	pthread_mutex_lock(&pool->lock);

	for (;;) {
		struct async_slot *slot = &pool->slots[pool->commit_next % pool->depth];
		uint8_t *buf;
		size_t buf_len;
		nmsg_container_t co;
		nmsg_res res = nmsg_res_success;

		switch (slot->state) {
		case slot_done:
			buf = slot->buf;
			buf_len = slot->buf_len;
			res = slot->res;
			slot->buf = NULL;
			pthread_mutex_unlock(&pool->lock);

			/*
			 * _output_nmsg_send_buffer() frees buf. It is not called when the
			 * compression failed, but then buf is NULL anyway; see
			 * _output_nmsg_container_compress().
			 */
			if (res == nmsg_res_success)
				res = _output_nmsg_send_buffer(pool->output, buf, buf_len);

			pthread_mutex_lock(&pool->lock);
			break;

		case slot_frag:
			co = slot->co;
			slot->co = NULL;
			pthread_mutex_unlock(&pool->lock);

			/* _output_nmsg_frag_write() takes the container by value and destroys it. */
			res = _output_nmsg_frag_write(pool->output, co);

			pthread_mutex_lock(&pool->lock);
			break;

		case slot_empty:
		case slot_work:
		case slot_taken:
			/*
			 * The next ticket is not ready. Exit only when the
			 * producers have stopped and every ticket they issued
			 * has been written.
			 */
			if (pool->shutdown && pool->commit_next >= pool->issued)
				goto out;
			pthread_cond_wait(&pool->commit_ready, &pool->lock);
			continue;
		}

		async_record_error(pool, res);
		slot->state = slot_empty;
		pool->commit_next++;
		pthread_cond_broadcast(&pool->slot_free);
	}

out:
	pthread_mutex_unlock(&pool->lock);

	return (NULL);
}

/*
 * Start the committer. Called under pool->lock on first submit rather than when
 * the output is configured, because nmsgtool creates its outputs before it
 * daemonizes, and daemonize() is a bare fork() which no thread survives.
 * Starting on first write puts the threads in whichever process does the
 * writing.
 *
 * Only the committer starts here. Workers are added by async_spawn_worker() as
 * load calls for them.
 */
static void
async_start(struct nmsg_ostr_async *pool)
{
	int pthread_res;

	pthread_res = pthread_create(&pool->committer, NULL, async_committer, pool);
	if (pthread_res != 0) {
		/*
		 * Nothing can be written without a committer, so give up on the
		 * pool entirely and compress inline from here on. No worker has
		 * been created yet and no container has been deposited, so there
		 * is nothing to unwind.
		 */
		pool->failed = true;
		_nmsg_dprintf(1, "%s: pthread_create() failed: %s\n", __func__,
			      strerror(pthread_res));
		return;
	}

	pool->started = true;
}

/*
 * Add a compressor thread, up to the ceiling. Called under pool->lock when a
 * producer finds every existing worker busy, so the pool grows to the load it
 * actually sees instead of to the configured ceiling.
 *
 * Returns false if the thread could not be created, which is not fatal: the
 * caller compresses that container itself and the pool keeps running with the
 * workers it has.
 */
static bool
async_spawn_worker(struct nmsg_ostr_async *pool)
{
	int pthread_res;

	pthread_res = pthread_create(&pool->workers[pool->nstarted], NULL,
				     async_worker, pool);
	if (pthread_res != 0) {
		/* Logged once; a persistent failure would flood the log. */
		if (!pool->spawn_failed) {
			pool->spawn_failed = true;
			_nmsg_dprintf(1, "%s: pthread_create() failed: %s\n",
				      __func__, strerror(pthread_res));
		}
		return (false);
	}

	pool->nstarted++;

	return (true);
}

/*
 * Wait until every ticket issued so far has been written, and take any error
 * the pool recorded. Under nmsg_io this cannot starve: check_close_event()
 * holds io_output->refcount across the write and call_close_fp() waits for it
 * to drop, so no other thread is inside nmsg_output_write() while a close runs.
 * A caller driving nmsg_output_flush() directly from several threads has no
 * such guarantee.
 */
nmsg_res
_output_async_drain(struct nmsg_ostr_async *pool)
{
	nmsg_res res;

	if (pool == NULL)
		return (nmsg_res_success);

	pthread_mutex_lock(&pool->lock);
	while (!pool->failed && pool->commit_next < pool->issued)
		pthread_cond_wait(&pool->slot_free, &pool->lock);
	res = pool->first_error;
	pool->first_error = nmsg_res_success;
	pthread_mutex_unlock(&pool->lock);

	return (res);
}

/*
 * Hand a sealed container to the pool, consuming it only if the pool takes it.
 * Returns false if it does not, and the caller writes the container itself.
 * The pool reference is released either way.
 *
 * On success *res_out carries the error from an EARLIER container, since the
 * one just handed over has not been written yet.
 */
bool
_output_async_submit(struct nmsg_ostr_async *pool, nmsg_output_t output,
		     nmsg_container_t *co, bool is_frag, uint64_t ticket,
		     nmsg_res *res_out)
{
	struct nmsg_stream_output *ostr = output->stream;
	struct async_slot *slot;
	nmsg_res res = nmsg_res_success;
	uint8_t *buf;
	size_t buf_len;
	bool inline_compress = false;

	pthread_mutex_lock(&pool->lock);

	if (!pool->started && !pool->failed && !pool->shutdown)
		async_start(pool);

	/*
	 * Only reachable when the committer could not be started: teardown drains
	 * outstanding tickets before setting shutdown, so a ticket that got this
	 * far still has a pool to go to.
	 */
	if (!pool->started || pool->failed || pool->shutdown) {
		pthread_mutex_unlock(&pool->lock);
		_output_async_unref(ostr);
		return (false);
	}

	slot = &pool->slots[ticket % pool->depth];

	/*
	 * Wait for the slot this ticket owns, which the ticket 'depth' earlier
	 * releases when it is written. Only reached when the writer has fallen
	 * a whole ring behind.
	 */
	if (ticket >= pool->commit_next + pool->depth) {
		pool->n_waited++;
		while (ticket >= pool->commit_next + pool->depth && !pool->shutdown)
			pthread_cond_wait(&pool->slot_free, &pool->lock);
	}

	assert(slot->state == slot_empty);

	if (ticket >= pool->issued)
		pool->issued = ticket + 1;

	if (is_frag) {
		/* Only the committer fragments; see async_committer(). */
		slot->co = *co;
		*co = NULL;
		slot->state = slot_frag;
		pthread_cond_broadcast(&pool->commit_ready);
	} else if (pool->busy < pool->nstarted ||
		   (pool->nstarted < pool->nworkers && async_spawn_worker(pool)))
	{
		/*
		 * A worker is free, or the ceiling left room to add one: hand
		 * the container over and get back to reading.
		 */
		slot->co = *co;
		*co = NULL;
		slot->state = slot_work;
		pool->busy++;
		pthread_cond_signal(&pool->work_ready);
	} else {
		/*
		 * Every worker is busy and the ceiling is reached. Compress it
		 * here rather than wait, then deposit the result and return.
		 */
		slot->state = slot_taken;
		pool->n_inline++;
		inline_compress = true;
	}

	res = pool->first_error;
	pool->first_error = nmsg_res_success;
	pthread_mutex_unlock(&pool->lock);

	if (inline_compress) {
		nmsg_res c_res = _output_nmsg_container_compress(output, co, &buf, &buf_len);

		pthread_mutex_lock(&pool->lock);
		slot->buf = buf;
		slot->buf_len = buf_len;
		slot->res = c_res;
		slot->state = slot_done;
		pthread_cond_broadcast(&pool->commit_ready);
		pthread_mutex_unlock(&pool->lock);
	}

	*res_out = res;
	_output_async_unref(ostr);

	return (true);
}
