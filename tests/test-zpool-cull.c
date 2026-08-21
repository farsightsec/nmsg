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
 * Compressors have to give their place back once they go idle, and the pool has
 * to grow again afterwards. Linked against libnmsg's own objects, since the
 * live worker count is not something the public headers expose.
 *
 * Only the first spawn is deterministic: a producer that finds no idle worker
 * starts one, so a single write guarantees exactly one. Growing past that needs
 * production to outrun compression, so nothing here asserts on it.
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "private.h"

#define BUFSZ		NMSG_WBUFSZ_JUMBO
#define CULL_SECS	1

/* Long enough that a CULL_SECS deadline has certainly passed. */
#define SETTLE_SECS	3

static nmsg_msgmod_t mod;

/* automake has no per-test timeout, so a wedged pool would hang forever. */
static void
on_alarm(int sig __attribute__((unused)))
{
	static const char msg[] = "test-zpool-cull: timed out\n";

	if (write(STDERR_FILENO, msg, sizeof(msg) - 1) != sizeof(msg) - 1) {
		/* Nothing useful to do; we are on our way out regardless. */
	}
	_exit(1);
}

static void
fail(const char *what)
{
	fprintf(stderr, "test-zpool-cull: %s\n", what);
	exit(1);
}

static void
fail_count(const char *what, unsigned want, unsigned got)
{
	fprintf(stderr, "test-zpool-cull: %s: wanted %u, got %u\n", what, want, got);
	exit(1);
}

static nmsg_message_t
make_message(unsigned i)
{
	char payload[48];
	nmsg_message_t msg;
	size_t len;

	msg = nmsg_message_init(mod);
	if (msg == NULL)
		fail("nmsg_message_init() failed");

	len = snprintf(payload, sizeof(payload), "payload %u", i);
	if (nmsg_message_set_field(msg, "payload", 0,
				   (const uint8_t *) payload, len) != nmsg_res_success)
		fail("nmsg_message_set_field() failed");

	return (msg);
}

static unsigned
count_payloads(const char *path)
{
	nmsg_input_t input;
	nmsg_message_t msg;
	unsigned n = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		fail("open() for reading failed");

	input = nmsg_input_open_file(fd);
	if (input == NULL)
		fail("nmsg_input_open_file() failed");

	while (nmsg_input_read(input, &msg) == nmsg_res_success) {
		nmsg_message_destroy(&msg);
		n += 1;
	}

	nmsg_input_close(&input);
	close(fd);

	return (n);
}

static nmsg_output_t
open_output(const char *path, unsigned workers, unsigned zmin, unsigned zcull)
{
	nmsg_output_t output;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		fail("open() for writing failed");

	output = nmsg_output_open_file(fd, BUFSZ);
	if (output == NULL)
		fail("nmsg_output_open_file() failed");

	nmsg_output_set_buffered(output, true);
	nmsg_output_set_zlibout(output, true);
	nmsg_output_set_zlib_cull(output, zmin, zcull);
	nmsg_output_set_zlib_workers(output, workers);

	return (output);
}

/* Write 'n' payloads and seal what they filled, so the pool sees a container. */
static void
write_burst(nmsg_output_t output, unsigned n, unsigned tag)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		nmsg_message_t msg = make_message(tag + i);

		if (nmsg_output_write(output, msg) != nmsg_res_success)
			fail("nmsg_output_write() failed");
		nmsg_message_destroy(&msg);
	}

	if (nmsg_output_flush(output) != nmsg_res_success)
		fail("nmsg_output_flush() failed");
}

static void
counts(nmsg_output_t output, unsigned *live, unsigned *peak, uint64_t *culled)
{
	struct nmsg_ostr_async *pool = output->stream->so_pool;

	if (pool == NULL)
		fail("output has no compressor pool");

	_output_async_counts(pool, live, peak, culled);
}

/*
 * A worker starts, goes quiet and gives its place back; the pool then grows
 * again from empty. Reaching zero is what exercises reusing a culled worker's
 * record, which means joining the thread that left it.
 */
static void
test_cull_to_empty(const char *path)
{
	nmsg_output_t output = open_output(path, 4, 0, CULL_SECS);
	unsigned live, peak;
	uint64_t culled;

	write_burst(output, 100, 0);
	counts(output, &live, &peak, &culled);
	if (live != 1)
		fail_count("worker not started", 1, live);

	sleep(SETTLE_SECS);

	counts(output, &live, &peak, &culled);
	if (live != 0)
		fail_count("pool did not empty", 0, live);
	if (culled != 1)
		fail_count("culls recorded", 1, (unsigned) culled);

	/* Growing again has to reuse the record the culled worker left. */
	write_burst(output, 100, 100);
	counts(output, &live, &peak, &culled);
	if (live != 1)
		fail_count("pool did not grow again", 1, live);

	if (nmsg_output_close(&output) != nmsg_res_success)
		fail("nmsg_output_close() failed");

	if (count_payloads(path) != 200)
		fail_count("payloads written", 200, count_payloads(path));
}

/* The floor is left alone, however long the pool stays quiet. */
static void
test_floor(const char *path)
{
	nmsg_output_t output = open_output(path, 4, 1, CULL_SECS);
	unsigned live;
	uint64_t culled;

	write_burst(output, 100, 0);
	sleep(SETTLE_SECS);

	counts(output, &live, NULL, &culled);
	if (live != 1)
		fail_count("floor not held", 1, live);
	if (culled != 0)
		fail_count("culls below the floor", 0, (unsigned) culled);

	if (nmsg_output_close(&output) != nmsg_res_success)
		fail("nmsg_output_close() failed");
}

/* Culling off leaves the pool at its high water mark. */
static void
test_cull_disabled(const char *path)
{
	nmsg_output_t output = open_output(path, 4, 0, 0);
	unsigned live, peak;
	uint64_t culled;

	write_burst(output, 100, 0);
	counts(output, &live, &peak, &culled);
	if (live != peak)
		fail_count("workers lost before settling", peak, live);

	sleep(SETTLE_SECS);

	counts(output, &live, &peak, &culled);
	if (live != peak)
		fail_count("culled with culling disabled", peak, live);
	if (culled != 0)
		fail_count("culls with culling disabled", 0, (unsigned) culled);

	if (nmsg_output_close(&output) != nmsg_res_success)
		fail("nmsg_output_close() failed");
}

/*
 * A floor above the ceiling has nothing to cull, and must be lowered to it
 * rather than quietly disable the policy.
 */
static void
test_floor_above_ceiling(const char *path)
{
	nmsg_output_t output = open_output(path, 1, 8, CULL_SECS);
	unsigned live;

	write_burst(output, 100, 0);
	sleep(SETTLE_SECS);

	counts(output, &live, NULL, NULL);
	if (live != 1)
		fail_count("clamped floor not held", 1, live);

	if (nmsg_output_close(&output) != nmsg_res_success)
		fail("nmsg_output_close() failed");
}

/*
 * Work keeps flowing across culls: containers written while the pool is
 * shrinking and regrowing all have to arrive, in order.
 */
static void
test_traffic_across_culls(const char *path)
{
	nmsg_output_t output = open_output(path, 4, 0, CULL_SECS);
	unsigned round, live;

	for (round = 0; round < 3; round++) {
		write_burst(output, 100, round * 100);
		sleep(SETTLE_SECS);
	}

	counts(output, &live, NULL, NULL);
	if (live != 0)
		fail_count("pool did not settle", 0, live);

	if (nmsg_output_close(&output) != nmsg_res_success)
		fail("nmsg_output_close() failed");

	if (count_payloads(path) != 300)
		fail_count("payloads written", 300, count_payloads(path));
}

int main(void) {
	char path[] = "/tmp/nmsg-zpool-cull.XXXXXX";
	int fd;

	signal(SIGALRM, on_alarm);
	alarm(120);

	if (nmsg_init() != nmsg_res_success)
		fail("nmsg_init() failed");

	mod = nmsg_msgmod_lookup_byname("base", "encode");
	if (mod == NULL)
		fail("no base:encode message type");

	/* mkstemp() only to get a unique name; the writers reopen by path. */
	fd = mkstemp(path);
	if (fd < 0)
		fail("mkstemp() failed");
	close(fd);

	test_cull_to_empty(path);
	test_floor(path);
	test_cull_disabled(path);
	test_floor_above_ceiling(path);
	test_traffic_across_culls(path);

	unlink(path);

	return (0);
}
