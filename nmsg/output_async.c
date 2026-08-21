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
 * The compressor pool for a stream output. The reorder buffer, its slot states
 * and the threads that walk it are private here; output_nmsg.c submits sealed
 * containers and supplies the compress and write callbacks.
 */

/* Import. */

#include "private.h"

#ifdef __linux__
#include <sched.h>
#endif /* __linux__ */

/* Data structures. */

/*
 * A compressor pool: a ticket reorder buffer, up to nworkers compressor
 * threads and one committer thread.
 *
 * Containers are ticketed under c_lock as they are sealed. Compression runs on
 * whichever thread is free, but only the committer writes and only in ticket
 * order, so the byte stream matches the synchronous path.
 *
 * A producer that finds every worker busy compresses inline rather than wait,
 * so the pool is never slower than no pool. Workers spawn on demand, making
 * 'nworkers' a ceiling rather than an allocation.
 */

/*
 * Slots kept free for producers to deposit inline-compressed containers into
 * while every worker is busy. Without it a saturated pool would have nowhere
 * left to put anything.
 */
#define ASYNC_REORDER_MARGIN 8

/* Smallest reorder buffer worth allocating. */
#define ASYNC_DEPTH_MIN 16

typedef enum {
	slot_empty = 0, /* Free. */
	slot_work,	/* Container waiting for a compressor. */
	slot_taken,	/* A worker or a producer is compressing it. */
	slot_done,	/* Compressed, waiting its turn to be written. */
	slot_frag	/* Oversized: the committer must fragment it itself. */
} async_slot_state;

struct async_slot {
	async_slot_state state;
	nmsg_container_t co;  /* slot_work, slot_frag */
	uint8_t		*buf; /* slot_done */
	size_t		 buf_len;
	nmsg_res	 res;
};

struct nmsg_ostr_async {
	pthread_mutex_t lock;
	pthread_cond_t	work_ready;   /* A slot became slot_work. */
	pthread_cond_t	commit_ready; /* The committer's slot is ready. */
	pthread_cond_t	slot_free;    /* A slot became slot_empty. */
	/*
	 * The ticket reorder buffer. Slot i serves every ticket with (ticket %
	 * depth) == i, so a producer runs at most 'depth' tickets ahead of
	 * commit_next and waits only for ticket T - depth to be written.
	 */
	struct async_slot *slots;
	unsigned	   depth;
	unsigned	   nworkers;	/* Ceiling; workers start on demand. */
	unsigned	   nstarted;	/* Workers that exist and must be joined. */
	unsigned	   busy;	/* Containers assigned to workers. */
	uint64_t	   issued;	/* Highest ticket claimed, plus one. */
	uint64_t	   commit_next; /* Ticket allowed to write now. */
	bool		   shutdown;
	bool		   started;	 /* Committer exists; must be joined. */
	bool		   failed;	 /* No committer; stay inline. */
	bool		   spawn_failed; /* Worker spawn failed; logged once. */
	pthread_t	  *workers;
	pthread_t	   committer;
	nmsg_res	   first_error; /* Sticky; surfaced by flush. */
	nmsg_output_t	   output;
	uint64_t	   n_inline; /* Containers a producer compressed. */
	uint64_t	   n_waited; /* Producers that waited for a slot. */
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
void _output_async_unref(struct nmsg_stream_output *ostr)
{
	pthread_mutex_lock(&ostr->c_lock);
	assert(ostr->so_inflight > 0);
	if (--ostr->so_inflight == 0)
		pthread_cond_broadcast(&ostr->c_drained);
	pthread_mutex_unlock(&ostr->c_lock);
}

/*
 * How many slots a pool of this size needs.
 *
 * One slot per worker covers everything that can be in flight, and the margin
 * leaves room to deposit into. Past that, more depth only defers backpressure,
 * and what it would be covering for is a slow write -- which is single-threaded
 * on the committer, and no amount of depth helps.
 *
 * Sized here rather than fixed because the worker count spans an order of
 * magnitude across the boxes this runs on, and a buffer sized for the largest
 * is megabytes that a two-worker output never touches.
 */
static unsigned
async_depth_for(unsigned nworkers)
{
	unsigned depth = nworkers + ASYNC_REORDER_MARGIN;

	return (depth < ASYNC_DEPTH_MIN ? ASYNC_DEPTH_MIN : depth);
}

/*
 * Cores this process may run on. nmsgtool computes the same thing for its own
 * sizing, but sees only the public header and cannot reach this one.
 */
static long
async_ncpu(void)
{
	long ncpu = -1;
#ifdef __linux__
	cpu_set_t set;

	if (sched_getaffinity(0, sizeof(set), &set) == 0)
		ncpu = CPU_COUNT(&set);
#endif /* __linux__ */

	if (ncpu < 1)
		ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1)
		ncpu = 1;

	return (ncpu);
}

/*
 * Compressor threads one output may have. Compression is CPU-bound, so more
 * than one thread per core cannot help; past that they only add context
 * switches and reorder buffer.
 *
 * This is a backstop for callers passing an arbitrary count. nmsgtool sizes
 * its own request against the readers it is actually running.
 */
static unsigned
async_max_workers(void)
{
	long ncpu = async_ncpu();

	if (ncpu < ASYNC_DEPTH_MIN)
		ncpu = ASYNC_DEPTH_MIN;

	return ((unsigned)(ncpu - ASYNC_REORDER_MARGIN));
}

nmsg_res
_output_async_init(nmsg_output_t output, unsigned nworkers)
{
	struct nmsg_stream_output *ostr = output->stream;
	struct nmsg_ostr_async	  *pool;
	nmsg_res		   res, old_res = nmsg_res_success;
	unsigned		   depth, max_workers;
	bool			   same_ceiling;

	if (nworkers == 0)
		return (nmsg_res_success);

	max_workers = async_max_workers();
	if (nworkers > max_workers)
		nworkers = max_workers;

	depth = async_depth_for(nworkers);

	/*
	 * A pool's ceiling cannot change in place, so a different count means
	 * a replacement. Build it before tearing the old one down, so a failed
	 * allocation leaves the working pool in place.
	 */
	same_ceiling = ostr->so_pool != NULL &&
		       ostr->so_pool->nworkers == nworkers;
	if (same_ceiling)
		return (nmsg_res_success);

	pool = calloc(1, sizeof(*pool));
	if (pool == NULL)
		return (nmsg_res_memfail);

	res = nmsg_res_memfail;

	pool->slots = calloc(depth, sizeof(*pool->slots));
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

	pool->depth = depth;
	pool->nworkers = nworkers;
	pool->output = output;

	if (ostr->so_pool != NULL)
		old_res = _output_async_destroy(output);

	pthread_mutex_lock(&ostr->c_lock);

	/*
	 * Tickets span the stream, not the pool, so a pool built mid-stream
	 * must start where the stream got to. Seeded and published in one
	 * c_lock hold, so a ticket either predates the pool or is at or above
	 * commit_next -- never below, where the committer would wait for it
	 * forever.
	 */
	pool->commit_next = pool->issued = ostr->so_ticket;

	/* Carry the old pool's unreported error rather than swallow it. */
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
 * Stop the pool and reclaim it, writing everything still queued. Must run
 * before the stream's fd, random and locks go away; the threads use all three.
 */
nmsg_res
_output_async_destroy(nmsg_output_t output)
{
	struct nmsg_stream_output *ostr = output->stream;
	struct nmsg_ostr_async	  *pool = ostr->so_pool;
	nmsg_res		   res;
	bool			   started;
	unsigned		   i, nstarted;

	if (pool == NULL)
		return (nmsg_res_success);

	/*
	 * Stop issuing tickets to the pool, then wait for the outstanding ones
	 * to arrive. Both under c_lock, which orders them against issuance:
	 * once this returns, no producer is still en route with a ticket.
	 */
	pthread_mutex_lock(&ostr->c_lock);
	ostr->so_pool_closing = true;
	while (ostr->so_inflight > 0)
		pthread_cond_wait(&ostr->c_drained, &ostr->c_lock);
	pthread_mutex_unlock(&ostr->c_lock);

	pthread_mutex_lock(&pool->lock);
	pool->shutdown = true;	 /* Set under the lock: a thread about */
	started = pool->started; /* to wait would miss the wakeup. */
	nstarted = pool->nstarted;
	pthread_cond_broadcast(&pool->work_ready);
	pthread_cond_broadcast(&pool->commit_ready);
	pthread_cond_broadcast(&pool->slot_free);
	pthread_mutex_unlock(&pool->lock);

	for (i = 0; i < nstarted; i++)
		pthread_join(pool->workers[i], NULL);
	if (started)
		pthread_join(pool->committer, NULL);

	if (pool->n_inline > 0 || pool->n_waited > 0)
		_nmsg_dprintf(2, "%s: %u of %u worker(s) started, %u slot(s); %" PRIu64 " container(s) compressed by the reader, %" PRIu64 " wait(s) for a free slot\n", __func__, nstarted,
			      pool->nworkers, pool->depth, pool->n_inline, pool->n_waited);

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
 * The slot this ticket owns is still held by the ticket 'depth' earlier.
 * Caller holds pool->lock.
 */
static bool
async_slot_busy(const struct nmsg_ostr_async *pool, uint64_t ticket)
{
	return (ticket >= pool->commit_next + pool->depth);
}

/*
 * Every ticket the pool was given has been written. Caller holds pool->lock.
 */
static bool
async_all_written(const struct nmsg_ostr_async *pool)
{
	return (pool->commit_next >= pool->issued);
}

/*
 * Compressor thread. Takes any slot needing work, in any order: only write
 * order matters, and the committer enforces that.
 */
static void *
async_worker(void *arg)
{
	struct nmsg_ostr_async *pool = (struct nmsg_ostr_async *)arg;

	pthread_mutex_lock(&pool->lock);

	for (;;) {
		struct async_slot *slot = NULL;
		nmsg_container_t   co;
		uint8_t		  *buf;
		size_t		   buf_len;
		nmsg_res	   res;
		unsigned	   i;

		for (i = 0; i < pool->depth; i++) {
			if (pool->slots[i].state == slot_work) {
				slot = &pool->slots[i];
				break;
			}
		}

		if (slot == NULL) {
			/*
			 * Exit only once producers have stopped, so a
			 * container queued just before shutdown is still
			 * written. Happens on every clean SIGTERM.
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
		pool->busy--; /* Counted at deposit; see container_submit(). */
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
 * The only thread that writes, and the only caller of
 * _output_nmsg_frag_write(). Takes tickets strictly in order, so the file
 * matches what the synchronous path would have produced.
 */
static void *
async_committer(void *arg)
{
	struct nmsg_ostr_async *pool = (struct nmsg_ostr_async *)arg;

	pthread_mutex_lock(&pool->lock);

	for (;;) {
		struct async_slot *slot = &pool->slots[pool->commit_next % pool->depth];
		uint8_t		  *buf;
		size_t		   buf_len;
		nmsg_container_t   co;
		nmsg_res	   res = nmsg_res_success;

		switch (slot->state) {
		case slot_done:
			buf = slot->buf;
			buf_len = slot->buf_len;
			res = slot->res;
			slot->buf = NULL;
			pthread_mutex_unlock(&pool->lock);

			/*
			 * _output_nmsg_send_buffer() frees buf; not called on
			 * a compression failure, where buf is NULL anyway.
			 */
			if (res == nmsg_res_success)
				res = _output_nmsg_send_buffer(pool->output, buf, buf_len);

			pthread_mutex_lock(&pool->lock);
			break;

		case slot_frag:
			co = slot->co;
			slot->co = NULL;
			pthread_mutex_unlock(&pool->lock);

			/* Takes the container by value and destroys it. */
			res = _output_nmsg_frag_write(pool->output, co);

			pthread_mutex_lock(&pool->lock);
			break;

		case slot_empty:
		case slot_work:
		case slot_taken:
			/*
			 * Not ready. Exit only once producers have stopped and
			 * every ticket they issued has been written.
			 */
			if (pool->shutdown && async_all_written(pool))
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
 * Start the committer, under pool->lock on first submit rather than at
 * configure time: nmsgtool creates its outputs before daemonize(), which is a
 * bare fork() no thread survives. Workers are added later by
 * async_spawn_worker().
 */
static void
async_start(struct nmsg_ostr_async *pool)
{
	int pthread_res;

	pthread_res = pthread_create(&pool->committer, NULL, async_committer, pool);
	if (pthread_res != 0) {
		/*
		 * Nothing can be written without a committer, so abandon the
		 * pool and compress inline. Nothing has been deposited yet to
		 * unwind.
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
 * producer finds every worker busy, so the pool grows to the load it sees.
 *
 * Returns false if the thread could not be created: not fatal, the caller
 * compresses that container itself.
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
 * holds io_output->refcount across the write, so no writer is inside
 * nmsg_output_write() while a close runs. Callers driving nmsg_output_flush()
 * from several threads have no such guarantee.
 */
nmsg_res
_output_async_drain(struct nmsg_ostr_async *pool)
{
	nmsg_res res;

	if (pool == NULL)
		return (nmsg_res_success);

	pthread_mutex_lock(&pool->lock);
	while (!pool->failed && !async_all_written(pool))
		pthread_cond_wait(&pool->slot_free, &pool->lock);
	res = pool->first_error;
	pool->first_error = nmsg_res_success;
	pthread_mutex_unlock(&pool->lock);

	return (res);
}

/*
 * Hand a sealed container to the pool, consuming it only if the pool takes it.
 * Returns false if it does not, leaving it for the caller to write. The pool
 * reference is released either way.
 *
 * *res_out carries an EARLIER container's error; this one is not written yet.
 */
bool _output_async_submit(struct nmsg_ostr_async *pool, nmsg_output_t output,
			  nmsg_container_t *co, bool is_frag, uint64_t ticket,
			  nmsg_res *res_out)
{
	struct nmsg_stream_output *ostr = output->stream;
	struct async_slot	  *slot;
	nmsg_res		   res = nmsg_res_success;
	uint8_t			  *buf;
	size_t			   buf_len;
	bool			   inline_compress = false;
	bool			   committer_needed, pool_usable;
	bool			   worker_idle, below_ceiling;

	pthread_mutex_lock(&pool->lock);

	committer_needed = !pool->started && !pool->failed && !pool->shutdown;
	if (committer_needed)
		async_start(pool);

	/*
	 * Read after the attempt, since async_start() sets started or failed.
	 * Only false when the committer could not start: teardown drains
	 * outstanding tickets before setting shutdown.
	 */
	pool_usable = pool->started && !pool->failed && !pool->shutdown;
	if (!pool_usable) {
		pthread_mutex_unlock(&pool->lock);
		_output_async_unref(ostr);
		return (false);
	}

	slot = &pool->slots[ticket % pool->depth];

	/*
	 * Wait for the slot this ticket owns, released by the ticket 'depth'
	 * earlier. Only reached when the writer is a full 'depth' behind.
	 */
	if (async_slot_busy(pool, ticket)) {
		pool->n_waited++;
		while (async_slot_busy(pool, ticket) && !pool->shutdown)
			pthread_cond_wait(&pool->slot_free, &pool->lock);
	}

	assert(slot->state == slot_empty);

	if (ticket >= pool->issued)
		pool->issued = ticket + 1;

	worker_idle = pool->busy < pool->nstarted;
	below_ceiling = pool->nstarted < pool->nworkers;

	if (is_frag) {
		/* Only the committer fragments; see async_committer(). */
		slot->co = *co;
		*co = NULL;
		slot->state = slot_frag;
		pthread_cond_broadcast(&pool->commit_ready);
	} else if (worker_idle || (below_ceiling && async_spawn_worker(pool))) {
		/* Hand the container over and get back to reading. */
		slot->co = *co;
		*co = NULL;
		slot->state = slot_work;
		pool->busy++;
		pthread_cond_signal(&pool->work_ready);
	} else {
		/* Everyone busy and at the ceiling: compress here. */
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
