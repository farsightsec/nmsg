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
 * The compressor pool must not change what gets written, only who compresses
 * it. One producer writes the same payloads with a range of worker ceilings;
 * every resulting file has to be byte for byte identical.
 *
 * A small bufsz is what makes this worth running: it puts many more containers
 * in the file than a 1 MiB one would, so the slot ring wraps repeatedly and
 * producers exercise the path where every worker is busy.
 */

#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"

#define NUM_PAYLOADS	4000
#define BUFSZ		NMSG_WBUFSZ_JUMBO

/* Flush and check the file part-way through, at this payload. */
#define CHECKPOINT_AT	1500

/* Enable the pool at this payload in the late-enable run. */
#define LATE_ENABLE_AT	700

static nmsg_msgmod_t mod;

/*
 * A wedged pool would otherwise hang the test suite forever: automake has no
 * per-test timeout, so the test has to impose its own.
 */
static void
on_alarm(int sig __attribute__((unused)))
{
	static const char msg[] = "test-zpool-order: timed out\n";

	if (write(STDERR_FILENO, msg, sizeof(msg) - 1) != sizeof(msg) - 1) {
		/* Nothing useful to do; we are on our way out regardless. */
	}
	_exit(1);
}

static void
fail(const char *what)
{
	fprintf(stderr, "test-zpool-order: %s\n", what);
	exit(1);
}

/*
 * Payloads are deliberately short. A payload larger than bufsz would take the
 * fragmenting path, whose fragment id is drawn from the RNG, and the output
 * would then differ between two identical runs for reasons that have nothing
 * to do with the pool.
 */
static nmsg_message_t
make_message(unsigned i)
{
	char payload[48];
	nmsg_message_t msg;
	struct timespec ts;
	size_t len;

	msg = nmsg_message_init(mod);
	if (msg == NULL)
		fail("nmsg_message_init() failed");

	len = snprintf(payload, sizeof(payload), "payload %u", i);
	if (len >= BUFSZ / 2)
		fail("payload too large; would fragment");

	if (nmsg_message_set_field(msg, "payload", 0,
				   (const uint8_t *) payload, len) != nmsg_res_success)
		fail("nmsg_message_set_field() failed");

	/* Fixed, so two runs cannot differ on the timestamp. */
	ts.tv_sec = 1000000000 + i;
	ts.tv_nsec = 0;
	nmsg_message_set_time(msg, &ts);

	return (msg);
}

/* Payloads readable from a path right now. */
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

/*
 * Write the corpus to 'path'.
 *
 * workers is the ceiling handed to nmsg_output_set_zlib_workers(). late_enable
 * defers that call until the stream is already part-written, which is only safe
 * because the pool seeds itself from the stream's ticket counter. rate throttles
 * the writer so the committer falls behind and producers have to wait on a slot.
 */
static void
write_corpus(const char *path, unsigned workers, bool late_enable, nmsg_rate_t rate)
{
	nmsg_output_t output;
	unsigned i;
	int fd;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		fail("open() for writing failed");

	output = nmsg_output_open_file(fd, BUFSZ);
	if (output == NULL)
		fail("nmsg_output_open_file() failed");

	nmsg_output_set_buffered(output, true);
	nmsg_output_set_zlibout(output, true);
	if (rate != NULL)
		nmsg_output_set_rate(output, rate);
	if (!late_enable)
		nmsg_output_set_zlib_workers(output, workers);

	for (i = 0; i < NUM_PAYLOADS; i++) {
		nmsg_message_t msg = make_message(i);

		if (nmsg_output_write(output, msg) != nmsg_res_success)
			fail("nmsg_output_write() failed");
		nmsg_message_destroy(&msg);

		if (i == LATE_ENABLE_AT) {
			if (nmsg_output_flush(output) != nmsg_res_success)
				fail("nmsg_output_flush() failed");
			if (late_enable)
				nmsg_output_set_zlib_workers(output, workers);
		}

		/*
		 * A flush must leave everything written so far on disk, which
		 * is the contract every file rotation depends on. Checked while
		 * the output is still open, so it is the flush being tested and
		 * not the close.
		 */
		if (i == CHECKPOINT_AT) {
			unsigned seen;

			if (nmsg_output_flush(output) != nmsg_res_success)
				fail("nmsg_output_flush() failed");

			seen = count_payloads(path);
			if (seen != i + 1) {
				fprintf(stderr, "test-zpool-order: flush left "
					"%u of %u payloads on disk\n", seen, i + 1);
				exit(1);
			}
		}
	}

	if (nmsg_output_close(&output) != nmsg_res_success)
		fail("nmsg_output_close() failed");
}

static void
compare(const char *ref, const char *path, const char *what)
{
	FILE *fa, *fb;
	int ca, cb;
	long off = 0;

	fa = fopen(ref, "rb");
	fb = fopen(path, "rb");
	if (fa == NULL || fb == NULL)
		fail("fopen() for comparison failed");

	do {
		ca = getc(fa);
		cb = getc(fb);
		if (ca != cb) {
			fprintf(stderr, "test-zpool-order: %s differs from the "
				"inline output at byte %ld\n", what, off);
			exit(1);
		}
		off += 1;
	} while (ca != EOF);

	fclose(fa);
	fclose(fb);
}

int main(void) {
	static const unsigned counts[] = { 1, 4, 8 };
	char ref[] = "/tmp/nmsg-zpool-ref.XXXXXX";
	char out[] = "/tmp/nmsg-zpool-out.XXXXXX";
	nmsg_rate_t rate;
	unsigned i;
	int fd;

	signal(SIGALRM, on_alarm);
	alarm(30);

	if (nmsg_init() != nmsg_res_success)
		fail("nmsg_init() failed");

	mod = nmsg_msgmod_lookup_byname("base", "encode");
	if (mod == NULL)
		fail("no base:encode message type");

	/* mkstemp() only to get unique names; the writers reopen by path. */
	fd = mkstemp(ref);
	if (fd < 0)
		fail("mkstemp() failed");
	close(fd);
	fd = mkstemp(out);
	if (fd < 0)
		fail("mkstemp() failed");
	close(fd);

	/* No pool: the reference every other run has to match. */
	write_corpus(ref, 0, false, NULL);

	if (count_payloads(ref) != NUM_PAYLOADS)
		fail("reference output is missing payloads");

	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		char what[64];

		snprintf(what, sizeof(what), "output with %u worker(s)", counts[i]);
		write_corpus(out, counts[i], false, NULL);
		compare(ref, out, what);
	}

	/* Pool enabled once the stream is already part-written. */
	write_corpus(out, 4, true, NULL);
	compare(ref, out, "output with the pool enabled mid-stream");

	/*
	 * Throttled, so the committer lags and the ring fills. This is the only
	 * run that reaches the slot wait in container_submit().
	 */
	rate = nmsg_rate_init(200, 1);
	if (rate == NULL)
		fail("nmsg_rate_init() failed");
	write_corpus(out, 4, false, rate);
	compare(ref, out, "rate-limited output");
	nmsg_rate_destroy(&rate);

	unlink(ref);
	unlink(out);

	return (0);
}