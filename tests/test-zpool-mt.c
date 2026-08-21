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
 * With several threads writing one output, the pool guarantees 
 * containers reach the file in the order they were
 * sealed. A thread's own payloads must therefore appear in the file in the
 * order that thread wrote them.
 *
 * This is a per-thread claim, not a global one. Which thread wins a given
 * container is a race, so nothing is asserted about how threads interleave --
 * only that no thread's payloads are reordered among themselves.
 *
 * Without a pool, container_submit() writes on the calling thread and two
 * threads race for w_lock in send_buffer(), so containers can reach the file
 * out of order. The check below therefore applies to the pooled runs only.
 */

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"

#define NUM_THREADS	4
#define PER_THREAD	5000
#define BUFSZ		NMSG_WBUFSZ_JUMBO

static nmsg_msgmod_t mod;
static nmsg_output_t output;

struct writer {
	pthread_t	thr;
	unsigned	id;
};

static void
on_alarm(int sig __attribute__((unused)))
{
	static const char msg[] = "test-zpool-mt: timed out\n";

	if (write(STDERR_FILENO, msg, sizeof(msg) - 1) != sizeof(msg) - 1) {
		/* On our way out regardless. */
	}
	_exit(1);
}

static void
fail(const char *what)
{
	fprintf(stderr, "test-zpool-mt: %s\n", what);
	exit(1);
}

static void *
writer_thread(void *arg)
{
	struct writer *w = (struct writer *) arg;
	unsigned i;

	for (i = 0; i < PER_THREAD; i++) {
		char payload[48];
		nmsg_message_t msg;
		size_t len;

		msg = nmsg_message_init(mod);
		if (msg == NULL)
			fail("nmsg_message_init() failed");

		len = snprintf(payload, sizeof(payload), "%u:%u", w->id, i);
		if (nmsg_message_set_field(msg, "payload", 0,
					   (const uint8_t *) payload,
					   len) != nmsg_res_success)
			fail("nmsg_message_set_field() failed");

		if (nmsg_output_write(output, msg) != nmsg_res_success)
			fail("nmsg_output_write() failed");
		nmsg_message_destroy(&msg);
	}

	return (NULL);
}

/*
 * Read the file back and check that each thread's counters only ever increase.
 * Returns the total number of payloads seen.
 */
static unsigned
verify_order(const char *path)
{
	unsigned last[NUM_THREADS];
	unsigned total = 0, i;
	nmsg_input_t input;
	nmsg_message_t msg;
	int fd;

	for (i = 0; i < NUM_THREADS; i++)
		last[i] = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		fail("open() for reading failed");

	input = nmsg_input_open_file(fd);
	if (input == NULL)
		fail("nmsg_input_open_file() failed");

	while (nmsg_input_read(input, &msg) == nmsg_res_success) {
		unsigned tid, seq;
		void *data;
		size_t len;
		char buf[64];

		if (nmsg_message_get_field(msg, "payload", 0, &data,
					   &len) != nmsg_res_success)
			fail("nmsg_message_get_field() failed");

		if (len >= sizeof(buf))
			fail("payload larger than expected");
		memcpy(buf, data, len);
		buf[len] = '\0';

		if (sscanf(buf, "%u:%u", &tid, &seq) != 2)
			fail("payload did not parse");
		if (tid >= NUM_THREADS)
			fail("payload carried an unknown thread id");

		/*
		 * Counters start at 0, so 'last' holds the next value expected
		 * rather than the previous one seen.
		 */
		if (seq != last[tid]) {
			fprintf(stderr, "test-zpool-mt: thread %u payload %u "
				"arrived where %u was expected\n",
				tid, seq, last[tid]);
			exit(1);
		}
		last[tid] = seq + 1;

		nmsg_message_destroy(&msg);
		total += 1;
	}

	nmsg_input_close(&input);
	close(fd);

	return (total);
}

static void
run(const char *path, unsigned workers)
{
	struct writer writers[NUM_THREADS];
	unsigned i, total;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		fail("open() for writing failed");

	output = nmsg_output_open_file(fd, BUFSZ);
	if (output == NULL)
		fail("nmsg_output_open_file() failed");

	nmsg_output_set_buffered(output, true);
	nmsg_output_set_zlibout(output, true);
	nmsg_output_set_zlib_workers(output, workers);

	for (i = 0; i < NUM_THREADS; i++) {
		writers[i].id = i;
		if (pthread_create(&writers[i].thr, NULL, writer_thread,
				   &writers[i]) != 0)
			fail("pthread_create() failed");
	}

	for (i = 0; i < NUM_THREADS; i++)
		pthread_join(writers[i].thr, NULL);

	if (nmsg_output_close(&output) != nmsg_res_success)
		fail("nmsg_output_close() failed");

	total = verify_order(path);
	if (total != NUM_THREADS * PER_THREAD) {
		fprintf(stderr, "test-zpool-mt: read %u payloads, expected %u\n",
			total, NUM_THREADS * PER_THREAD);
		exit(1);
	}
}

int main(void) {
	char path[] = "/tmp/nmsg-zpool-mt.XXXXXX";
	int fd;

	signal(SIGALRM, on_alarm);
	alarm(60);

	if (nmsg_init() != nmsg_res_success)
		fail("nmsg_init() failed");

	mod = nmsg_msgmod_lookup_byname("base", "encode");
	if (mod == NULL)
		fail("no base:encode message type");

	fd = mkstemp(path);
	if (fd < 0)
		fail("mkstemp() failed");
	close(fd);

	run(path, 1);
	run(path, 4);

	unlink(path);

	return (0);
}