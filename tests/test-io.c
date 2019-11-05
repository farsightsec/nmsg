/*
 * Copyright (c) 2018 by Farsight Security, Inc.
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <pthread.h>

#include "errors.h"

#include "nmsg.h"
#include "nmsg/asprintf.h"
#include "nmsg/alias.h"
#include "nmsg/chalias.h"
#include "nmsg/container.h"
#include "nmsg/msgmod.h"
#include "nmsg/vendors.h"
#include "nmsg/base/defs.h"

#include "wdns.h"

#define NAME	"test-io"

#define UDP_PORT_BASE	10000
#define UDP_PORT_END	11000



static void
dummy_callback(nmsg_message_t msg, void *user)
{
	(void)(msg);
	(void)(user);
	return;
}

/* Create and populate dummy base:packet message from scratch. */
static int
make_message(nmsg_message_t *mout)
{
	nmsg_message_t m;
	nmsg_msgmod_t mm;
	size_t nf, ulen;
	void *uptr = NULL;
	const char *test_payload = "bla bla bla";
	uint32_t u32v = 1; /* NMSG__BASE__PACKET_TYPE__IP */

	mm = nmsg_msgmod_lookup_byname("base", "packet");
	check_return(mm != NULL);

	m = nmsg_message_init(mm);

	check_return(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	check_return(nf == 2);

	uptr = (uint8_t *)&u32v;
	check_return(nmsg_message_set_field(m, "payload_type", 0, uptr, 4) == nmsg_res_success);

	check_return(nmsg_message_set_field(m, "payload", 0, (uint8_t *)test_payload, strlen(test_payload) + 1) == nmsg_res_success);

	check(nmsg_message_get_field(m, "payload", 0, &uptr, &ulen) == nmsg_res_success);
	check(ulen >= sizeof(test_payload));
	check(uptr && !strcmp(test_payload, uptr));

	*mout = m;

	return 0;
}

static int sockspec_wrote = 0;

static void
sockspec_output_callback(nmsg_message_t msg, void *user)
{
	(void)(msg);
	nmsg_io_t io = (nmsg_io_t)user;

	sockspec_wrote = 1;
	nmsg_io_breakloop(io);

	return;
}

/* Test adding an nmsg io input via sockspec address specification. */
static int
test_io_sockspec(void)
{
	nmsg_io_t io;
	nmsg_output_t o1, o2;
	nmsg_message_t m;
	struct sockaddr_in s_in;
	unsigned short lport = UDP_PORT_BASE;
	char sockstr[64];
	int fd;

	/* Test to see that we can bind to the desired port. */
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	check_return(fd != -1);

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = AF_INET;
	s_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_in.sin_port = htons(lport);
	check_return(bind(fd, (struct sockaddr *)&s_in, sizeof(s_in)) != -1);
	close(fd);

	/* Create the nmsg io using that same good listen-able port. */
	io = nmsg_io_init();
	check_return(io != NULL);

	snprintf(sockstr, sizeof(sockstr), "127.0.0.1/%u", lport);
	check_return(nmsg_io_add_input_sockspec(io, sockstr, NULL) == nmsg_res_success);

	/* Now create a socket to be connected to that port and send it data. */
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	check_return(fd != -1);

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = AF_INET;
	s_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_in.sin_port = htons(lport);
	check_return(connect(fd, (struct sockaddr *)&s_in, sizeof(s_in)) != -1);

	o2 = nmsg_output_open_sock(fd, 8192);
	check_return(o2 != NULL);

	nmsg_output_set_buffered(o2, false);

	/* Set our callback and send the packet. */
	o1 = nmsg_output_open_callback(sockspec_output_callback, io);
	check_return(o1 != NULL);

	return_if_error(make_message(&m));

	check_return(nmsg_io_add_output(io, o1, NULL) == nmsg_res_success);
	check_return(nmsg_output_write(o2, m) == nmsg_res_success);

	nmsg_message_destroy(&m);

	/* Make sure we received that packet OK. */
	check(nmsg_io_loop(io) == nmsg_res_success);

	check(sockspec_wrote == 1);

	check(nmsg_output_close(&o1) == nmsg_res_success);
	check(nmsg_output_close(&o2) == nmsg_res_success);

	l_return_test_status();
}

/* Test buffered and unbuffered output via nmsg_input_open_sock(); test output filters */
static int
test_sock(void)
{
	nmsg_output_t o;
	nmsg_input_t i;
	nmsg_message_t mo, mi;
	struct timespec tnow, xtime;
	struct sockaddr_in s_in;
	int sfd, cfd;
	unsigned int nsrc = 0x1234;
	unsigned short lport = UDP_PORT_BASE;
	uint64_t count;

	/* Create a server and client UDP socket and connect them. */
	sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	check_return(sfd != -1);

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = AF_INET;
	s_in.sin_addr.s_addr = inet_addr("127.0.0.1");
	s_in.sin_port = htons(lport);
	check_return(bind(sfd, (struct sockaddr *)&s_in, sizeof(s_in)) != -1);

	cfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	check_return(cfd != -1);
	check_return(connect(cfd, (struct sockaddr *)&s_in, sizeof(s_in)) != -1);

	i = nmsg_input_open_sock(sfd);
	check_return(i != NULL);

	o = nmsg_output_open_sock(cfd, 8192);
	check_return(o != NULL);

	nmsg_output_set_source(o, nsrc);

	/* First write is unbuffered. */
	return_if_error(make_message(&mo));
	nmsg_output_set_buffered(o, false);
	check_return(nmsg_output_write(o, mo) == nmsg_res_success);

	check_return(nmsg_input_read(i, &mi) == nmsg_res_success);

	check(nmsg_message_get_vid(mi) == NMSG_VENDOR_BASE_ID);
	check(nmsg_message_get_msgtype(mi) == NMSG_VENDOR_BASE_PACKET_ID);
	check(nmsg_message_get_source(mi) == nsrc);
	check(nmsg_message_get_operator(mi) == 0);

	nmsg_message_destroy(&mo);

	/* Second write is buffered and must be flushed. */
	return_if_error(make_message(&mo));
	nmsg_output_set_buffered(o, true);
	check_return(nmsg_output_write(o, mo) == nmsg_res_success);
	check_return(nmsg_output_flush(o) == nmsg_res_success);

	check(nmsg_input_read(i, &mi) == nmsg_res_success);
	nmsg_message_destroy(&mo);

	/* Third write should be filtered by output, since it won't match. */
	nmsg_output_set_filter_msgtype_byname(o, "base", "dnsqr");
	return_if_error(make_message(&mo));
	check_return(nmsg_output_write(o, mo) == nmsg_res_success);
	check_return(nmsg_output_flush(o) == nmsg_res_success);

	check(nmsg_input_read(i, &mi) == nmsg_res_again);
	nmsg_message_destroy(&mo);

	/* Fourth write will have a filter that WILL match. */
	nmsg_output_set_filter_msgtype(o, NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_PACKET_ID);
	return_if_error(make_message(&mo));
	check_return(nmsg_output_write(o, mo) == nmsg_res_success);
	check_return(nmsg_output_flush(o) == nmsg_res_success);

	check_return(nmsg_input_read(i, &mi) == nmsg_res_success);

	check(nmsg_message_get_payload(mi) != NULL);
	check(nmsg_message_get_payload_size(mi) == 36);

	nmsg_message_destroy(&mo);

	/* Test some other random things. */
	nmsg_output_set_operator(o, 456);
	nmsg_output_set_group(o, 666);
	return_if_error(make_message(&mo));
	check_return(nmsg_output_write(o, mo) == nmsg_res_success);
	check_return(nmsg_output_flush(o) == nmsg_res_success);

	check_return(nmsg_input_read(i, &mi) == nmsg_res_success);
	nmsg_message_destroy(&mo);

	check(nmsg_message_get_group(mi) == 666);
	check(nmsg_message_get_operator(mi) == 456);

	nmsg_message_get_time(mi, &xtime);
	nmsg_timespec_get(&tnow);
	check(tnow.tv_sec >= xtime.tv_sec);

	check(nmsg_input_get_count_container_received(i, &count) == nmsg_res_success);
	check(count == 4);
	check(nmsg_input_get_count_container_dropped(i, &count) == nmsg_res_success);
	check(count == 0);

	check(nmsg_input_close(&i) == nmsg_res_success);
	check(nmsg_output_close(&o) == nmsg_res_success);

	l_return_test_status();
}

/* Test nmsg output use of zlib compression. */
static int
test_ozlib(void)
{
	nmsg_output_t o;
	nmsg_message_t mo;
	struct stat sb;
	FILE *f;
	int fd;
	size_t old_size;

	f = tmpfile();
	check_return(f != NULL);

	fd = fileno(f);
	check_return(fd != -1);

	o = nmsg_output_open_file(fd, 8192);
	check_return(o != NULL);

	/* Write a message with an easily compressed field. */
	return_if_error(make_message(&mo));
	const char *rrpayload = "\x03""www""\x50""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""\x03""com""\x0";
	check_return(nmsg_message_set_field(mo, "payload", 0, (uint8_t *)rrpayload, strlen(rrpayload) + 1) == nmsg_res_success);

	nmsg_output_set_buffered(o, false);
	check_return(nmsg_output_write(o, mo) == nmsg_res_success);

	check_return(fstat(fd, &sb) != -1);
	old_size = sb.st_size;
	check_return(lseek(fd, SEEK_SET, 0) == 0);
	check_return(ftruncate(fd, 0) != -1);

	/* Rewrite the file with some compression turned on. New output should be smaller. */
	nmsg_output_set_zlibout(o, true);
	check_return(nmsg_output_write(o, mo) == nmsg_res_success);
	check_return(fstat(fd, &sb) != -1);
	check(sb.st_size < (off_t)old_size);

	nmsg_message_destroy(&mo);
	check(nmsg_output_close(&o) == nmsg_res_success);

	fclose(f);

	l_return_test_status();
}

/* Test the functionality of nmsg input loops. */
static int
test_dummy(void)
{
	nmsg_input_t i, ij;
	nmsg_container_t c;
	nmsg_message_t m, *ms;
	nmsg_res res;
	uint8_t *buf;
	size_t n_ms = 0, nn_ms, bufsz;
	int fd;

	/* First create a container and load it up. */
	fd = open(SRCDIR "/tests/generic-tests/dedupe.json", O_RDONLY);
	check_return(fd != -1);

	ij = nmsg_input_open_json(fd);
	check_return(ij != NULL);

	c = nmsg_container_init(8192);
	check_return(c != NULL);

	while ((res = nmsg_input_read(ij, &m)) == nmsg_res_success) {
		n_ms++;
		check_return(nmsg_container_add(c, m) == nmsg_res_success);
	}

	check_return(res == nmsg_res_eof);

	/* Serialize the container and then read it through the null type */
	check_return(nmsg_container_serialize(c, &buf, &bufsz, true, false, 0, 0) == nmsg_res_success);

	i = nmsg_input_open_null();
	check_return(i != NULL);

	/*
	 * Directly from the nmsg comments:
	 *
	 * Calling nmsg_input_loop() or nmsg_input_read() on a "null source" input
	 * will fail. Callers instead need to use nmsg_input_read_null().
	 */
	check_return(nmsg_input_loop(i, 1, dummy_callback, NULL) != nmsg_res_success);
	check(nmsg_input_read(i, &m) != nmsg_res_success);

	check_return(nmsg_input_read_null(i, buf, bufsz, NULL, &ms, &nn_ms) == nmsg_res_success);
	check(n_ms == nn_ms);

	check(nmsg_input_close(&ij) == nmsg_res_success);
	check(nmsg_input_close(&i) == nmsg_res_success);
	nmsg_container_destroy(&c);

	l_return_test_status();
}

/* Chop up a string into an array of sorted lines. */
static char **
chop_lines_sorted(const char *s, size_t nlines)
{
	char **result;
	const char *sptr = s;
	size_t n;

	result = malloc(sizeof(*result) * nlines);
	check_abort(result != NULL);
	memset(result, 0, (sizeof(*result) * nlines));

	for (n = 0; n < nlines; n++) {
		const char *end;
		int done = 0;

		end = strchr(sptr, '\n');

		if (!end) {
			done = 1;
			end = sptr + strlen(sptr);
		}

		result[n] = strndup(sptr, end - sptr);
		check_abort(result[n] != NULL);

		if (done)
			break;

		sptr = end + 1;
	}

	if (n != nlines)
		return NULL;

	for (n = 1; n < nlines; n++) {

		if (strcmp(result[n - 1], result[n]) < 0) {
			char *tmp = result[n - 1];

			result[n - 1] = result[n];
			result[n] = tmp;
			n = 0;
		}

	}

	return result;
}

static void
free_str_lines(char **l, size_t nlines)
{
	size_t n;

	if (!l)
		return;

	for (n = 0; n < nlines; n++) {

		if (l[n])
			free(l[n]);

		l[n] = NULL;
	}

	free(l);
	return;
}

/* Count the number of lines in a string. */
static size_t
count_lines(const char *s)
{
	const char *sptr = s;
	size_t count = 0;

	while (sptr && *sptr) {
		count++;

		sptr = strchr(sptr, '\n');

		if (sptr)
			sptr++;

	}

	return count;
}

/*
 * Compare two strings as a collection of ordered strings.
 *
 * Since this is a leaf function called by other tests,
 * we don't even bother with returning 1 or -1;
 * any non-zero return is simply treated an error.
 */
static int
compare_string_sets(const char *s1, const char *s2)
{
	char **ss1, **ss2;
	size_t n, l1, l2;
	int result = 0;

	l1 = count_lines(s1);
	l2 = count_lines(s2);

	check_return(l1 == l2);

	ss1 = chop_lines_sorted(s1, l1);
	check_return(ss1 != NULL);
	ss2 = chop_lines_sorted(s2, l2);
	check_return(ss2 != NULL);

	for (n = 0; n < l1; n++) {
		int res;

		res = strcmp(ss1[n], ss2[n]);

		if (res != 0) {
			result = res;
			break;
		}

	}

	free_str_lines(ss1, l1);
	free_str_lines(ss2, l2);

	check_return(result == 0);

	return 0;
}


 /*
  * Test nmsg I/O loop with a variety of inputs and outputs.
  * In the process, check out nmsg_io_set_output_mode().
  */
static int
test_multiplex(void)
{
	void *user = (void *)0xdeadbeef;
	size_t i = 0;
	size_t total = 0;

	/* The two iterations of this loop correspond to mirror and striped output mode. */
	while (i < 2) {
		nmsg_io_t io;
		nmsg_input_t i1, i2, i3;
		nmsg_output_t o1, o2;
		int fd, pipe_fds1[2], pipe_fds2[2], nread;
		size_t first_total = 0, second_total = 0;
		char tmpbuf1[8192*4] = {0}, tmpbuf2[8192*4] = {0};

		io = nmsg_io_init();
		check_return(io != NULL);

		/* Set up a few (3) json-based inputs. */
		check(nmsg_io_get_num_inputs(io) == 0);

		fd = open(SRCDIR "/tests/generic-tests/dnsqr.json", O_RDONLY);
		check_return(fd != -1);
		i1 = nmsg_input_open_json(fd);
		check_return(i1 != NULL);
		check_return(nmsg_io_add_input(io, i1, NULL) == nmsg_res_success);

		fd = open(SRCDIR "/tests/generic-tests/dnsqr.json", O_RDONLY);
		check_return(fd != -1);
		i2 = nmsg_input_open_json(fd);
		check_return(i1 != NULL);
		check_return(nmsg_io_add_input(io, i2, NULL) == nmsg_res_success);

		fd = open(SRCDIR "/tests/generic-tests/packet.json", O_RDONLY);
		check_return(fd != -1);
		i3 = nmsg_input_open_json(fd);
		check_return(i3 != NULL);
		check_return(nmsg_io_add_input(io, i3, NULL) == nmsg_res_success);

		check(nmsg_io_get_num_inputs(io) == 3);
		check(nmsg_io_get_num_outputs(io) == 0);

		/* Set up a pair of outputs to write to our pipes. */
		check_return(pipe(pipe_fds1) != -1);
		check_return(pipe(pipe_fds2) != -1);

		o1 = nmsg_output_open_json(pipe_fds1[1]);
		check_return(o1 != NULL);
		o2 = nmsg_output_open_json(pipe_fds2[1]);
		check_return(o2 != NULL);

		check_return(nmsg_io_add_output(io, o1, user) == nmsg_res_success);
		check_return(nmsg_io_add_output(io, o2, user) == nmsg_res_success);
		check_return(nmsg_io_get_num_outputs(io) == 2);

		/* We have two runs: one for mirrored and one for striped mode. */
		if (!i)
			nmsg_io_set_output_mode(io, nmsg_io_output_mode_mirror);
		else
			nmsg_io_set_output_mode(io, nmsg_io_output_mode_stripe);

		check_return(nmsg_io_loop(io) == nmsg_res_success);

		nmsg_io_destroy(&io);
		check(io == NULL);

		/* Read what was written to our pipes by our 2 nmsg outputs. */
		while (first_total < (sizeof(tmpbuf1) - 1)) {
			nread = read(pipe_fds1[0], tmpbuf1 + first_total, (sizeof(tmpbuf1) - 1) - first_total);

			if (nread <= 0)
				break;

			first_total += nread;
		}

		while (second_total < (sizeof(tmpbuf2) - 1)) {
			nread = read(pipe_fds2[0], tmpbuf2 + second_total, (sizeof(tmpbuf2) - 1) - second_total);

			if (nread <= 0)
				break;

			second_total += nread;

		}

		close(pipe_fds1[0]);
		close(pipe_fds2[0]);

		if (!i) {
			/* In mirror mode we expect the exact same data written to both outputs. */
			total = first_total + second_total;
			check(first_total == second_total);
			return_if_error(compare_string_sets(tmpbuf1, tmpbuf2));
		} else {
			int diff;

			/*
			 * In striped mode, given the data set, we expect the data produced
			 * by each output to be differently sized, or at least different.
			 * We also expect the total # striped bytes written to be equal to
			 * half the total bytes written in mirror mode (which is duplicated).
			 */
			diff = (first_total != second_total ||
				(memcmp(tmpbuf1, tmpbuf2, first_total)));
			check(diff != 0);
			check(total == ((first_total + second_total) * 2));
		}

		i++;
	}

	l_return_test_status();
}


static int ioloop_stopped = 0;

/* Shut down an io loop if it is still active. */
static void *
threaded_stopper(void *arg)
{
	nmsg_io_t io = (nmsg_io_t )arg;

	sleep(3);

	if (!ioloop_stopped) {
		ioloop_stopped = 1;
		nmsg_io_breakloop(io);
	}

	return NULL;
}

/* Check to see that the nmsg_io_set_interval() function is working properly. */
static int
test_interval(void)
{
	nmsg_io_t io;
	nmsg_input_t i;
	nmsg_output_t o;
	int sfds[2];
	pthread_t p;
	struct timespec ts1, ts2;
	double elapsed;

	/* Make a socket pair that comprise a connected nmsg input and output. */
	check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, sfds) != -1);

	i = nmsg_input_open_sock(sfds[0]);
	check_return(i != NULL);

	o = nmsg_output_open_sock(sfds[1], 8192);
	check_return(o != NULL);

	io = nmsg_io_init();
	check_return(io != NULL);

	check_return(nmsg_io_add_input(io, i, NULL) == nmsg_res_success);
	check_return(nmsg_io_add_output(io, o, NULL) == nmsg_res_success);

	/* Our stopper thread will tear down the nmsg io if it stays alive too long. */
	check_abort(pthread_create(&p, NULL, threaded_stopper, io) == 0);

	/* Set interval = 1s (backup threaded timeout kicks in at +3s) */
	nmsg_io_set_interval(io, 1);
	nmsg_timespec_get(&ts1);
	check(nmsg_io_loop(io) == nmsg_res_success);
	nmsg_timespec_get(&ts2);

	/* Make sure we weren't forcibly shut down. */
	check(ioloop_stopped != 1);
	ioloop_stopped = 1;
	nmsg_timespec_sub(&ts1, &ts2);
	elapsed = nmsg_timespec_to_double(&ts2);
	/* Our elapsed window is 1s (interval) + .5s (NMSG_RBUF_TIMEOUT) + .05 fudge factor */
	fprintf(stderr, "elapsed = %f\n", elapsed);
	check(elapsed < 1.55);

	nmsg_io_destroy(&io);

	l_return_test_status();
}


typedef struct _iopair {
	nmsg_io_t io;
	nmsg_input_t i;
	nmsg_output_t o;
	int error;
} iopair;

static size_t n_looped = 0, max_looped = 5;

static void
counter_callback(nmsg_message_t msg, void *user)
{
	(void)(msg);
	iopair *iop = (iopair *)user;
	nmsg_message_t m;

	if (n_looped == max_looped)
		return;

	__sync_add_and_fetch(&n_looped, 1);

	if (n_looped >= max_looped) {
		nmsg_io_breakloop(iop->io);
		return;
	}

	if (nmsg_input_read(iop->i, &m) != nmsg_res_success)
		iop->error++;
	else {

		if (nmsg_output_write(iop->o, m) != nmsg_res_success)
			iop->error++;

	}

	return;
}

/* Test the enforcement of nmsg_io_set_count(). */
static int
test_count(void)
{
	size_t n = 0;

	/*
	 * Our source nmsg file is known to have 5 entries.
	 * We will read them one by one and send them to an nmsg io loop.
	 * The first run will have the count set to 15, meaning that all 5
	 * nmsg payloads should be processed. The second run will have the count
	 * set to 3, meaning that only 3 will be processed.
	 */
	while (n < 2) {
		nmsg_io_t io;
		nmsg_output_t o, o2;
		nmsg_input_t i, ri;
		nmsg_message_t m;
		iopair iop;
		int fd, sfds[2];

		n_looped = 0;

		/* Create a pair of sockets to transfer the nmsgs read from the json source file */
		check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, sfds) != -1);

		fd = open(SRCDIR "/tests/generic-tests/packet.json", O_RDONLY);
		check_return(fd != -1);

		i = nmsg_input_open_json(fd);
		check_return(i != NULL);

		ri = nmsg_input_open_sock(sfds[0]);
		check_return(ri != NULL);
		o = nmsg_output_open_sock(sfds[1], 8192);
		check_return(o != NULL);
		nmsg_output_set_buffered(o, false);

		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		check_return(nmsg_output_write(o, m) == nmsg_res_success);

		io = nmsg_io_init();
		check_return(io != NULL);

		check_return(nmsg_io_add_input(io, ri, NULL) == nmsg_res_success);

		o2 = nmsg_output_open_callback(counter_callback, &iop);
		check_return(o2 != NULL);
		check_return(nmsg_io_add_output(io, o2, NULL) == nmsg_res_success);

		/*
		 * Setting up a callback is the only way we can track our input
		 * count to verify that we received the expected amount.
		 */
		memset(&iop, 0, sizeof(iop));
		iop.io = io;
		iop.i = i;
		iop.o = o;

		if (!n)
			nmsg_io_set_count(io, 15);
		else
			nmsg_io_set_count(io, 3);

		check(nmsg_io_loop(io) == nmsg_res_success);

		check(iop.error == 0);

		if (!n) {
			check(n_looped == 5);
		} else {
			check(n_looped == 3);
		}

		nmsg_io_destroy(&io);
		check(io == NULL);

		check(nmsg_input_close(&i) == nmsg_res_success);
		check(nmsg_output_close(&o) == nmsg_res_success);

		n++;
	}

	l_return_test_status();
}

/*
 * Test a wide variety of nmsg input filter functions.
 */
static int
test_io_filters2(void)
{
	int n;

	for (n = 0; n < 11; n++) {
		nmsg_input_t i;
		nmsg_message_t m;
		int fd;

		fd = open(SRCDIR "/tests/generic-tests/dnsqr.nmsg", O_RDONLY);
		check_return(fd != -1);

		i = nmsg_input_open_file(fd);
		check_return(i != NULL);

		/* Only need to try this once. */
		if (!n) {
			check(nmsg_input_set_filter_msgtype_byname(i, "some_vendor", "nonexistent_type") != nmsg_res_success);
		}

		/* The ordering is particular. Every odd numbered test should
		 * succeed, and vice versa. */
		switch(n) {
			case 1:
				nmsg_input_set_filter_msgtype(i, NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_PACKET_ID);
				break;
			case 2:
				nmsg_input_set_filter_msgtype(i, NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_DNSQR_ID);
				break;
			case 3:
				nmsg_input_set_filter_group(i, 2835122346);
				break;
			case 4:
				nmsg_input_set_filter_group(i, 0);
				break;
			case 5:
				nmsg_input_set_filter_source(i, 1235817825);
				break;
			case 6:
				nmsg_input_set_filter_source(i, 0xa1ba02cf);
				break;
			case 7:
				nmsg_input_set_filter_operator(i, 138158152);
				break;
			case 8:
				nmsg_input_set_filter_operator(i, 0);
				break;
			case 9:
				check(nmsg_input_set_filter_msgtype_byname(i, "base", "packet") == nmsg_res_success);
				break;
			case 10:
				check(nmsg_input_set_filter_msgtype_byname(i, "base", "dnsqr") == nmsg_res_success);
				break;
			default:
				break;
		}

		if (!(n % 2)) {
			check(nmsg_input_read(i, &m) == nmsg_res_success);
		} else {
			check(nmsg_input_read(i, &m) != nmsg_res_success);
		}

		check(nmsg_input_close(&i) == nmsg_res_success);
		close(fd);
	}

	l_return_test_status();
}

/* Test nmsg rates and their effects on nmsg outputs with set rates. */
static int
test_rate(void)
{
	size_t all_rates[7] = { 30, 15, 10, 5, 4, 2, 1 };
	size_t n;
	double all_elapsed[7];

	memset(&all_elapsed, 0, sizeof(all_elapsed));

	for (n = 0; n < (sizeof(all_rates) / sizeof(all_rates[0])); n++) {
		struct timespec ts1, ts2;
		nmsg_rate_t r;
		nmsg_output_t o;
		nmsg_input_t i, ri;
		nmsg_message_t m;
		int fd, sfds[2];
		size_t n_success = 0;

		/* Create a pair of sockets to transfer the nmsgs read from the json source file */
		check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, sfds) != -1);

		fd = open(SRCDIR "/tests/generic-tests/packet.json", O_RDONLY);
		check_return(fd != -1);

		i = nmsg_input_open_json(fd);
		check_return(i != NULL);

		ri = nmsg_input_open_sock(sfds[0]);
		check_return(ri != NULL);
		o = nmsg_output_open_sock(sfds[1], 8192);
		check_return(o != NULL);
		nmsg_output_set_buffered(o, false);

		r = nmsg_rate_init(all_rates[n], 10);
		check_return(r != NULL);

		nmsg_output_set_rate(o, r);

		nmsg_timespec_get(&ts1);

		while (nmsg_input_read(i, &m) == nmsg_res_success) {
			n_success++;

			check_return(nmsg_output_write(o, m) == nmsg_res_success);
			check_return(nmsg_input_read(ri, &m) == nmsg_res_success);
		}

		nmsg_timespec_get(&ts2);

		/* Our source file had 5 nmsgs and each should have been written and read successfully. */
		check_return(n_success == 5);

		nmsg_timespec_sub(&ts1, &ts2);
		all_elapsed[n] = nmsg_timespec_to_double(&ts2);

		/* At least as much time should have elapsed since the previous attempt. */
		if (n > 0) {
			check(all_elapsed[n] > all_elapsed[n - 1]);
		}

		fprintf(stderr, "all_elapsed[%zu] = %f; all_rates[%zu] = %zu\n", n, all_elapsed[n], n, all_rates[n]);
		check(all_elapsed[n] < ((double)n_success * 1.056 / (double)all_rates[n]));

		check(nmsg_input_close(&i) == nmsg_res_success);
		check(nmsg_output_close(&o) == nmsg_res_success);
		nmsg_rate_destroy(&r);
	}

	l_return_test_status();
}


static void *user_data = (void *)0xdeadbeef;
static int touched_exit, touched_atstart, touched_close, num_received, touched_filter;

static void
test_close_fp(struct nmsg_io_close_event *ce)
{
	(void)(ce);
	__sync_add_and_fetch(&touched_close, 1);

	return;
}

static void
test_atstart_fp(unsigned threadno, void *user)
{
	(void)(threadno);

	if (user == user_data)
		__sync_add_and_fetch(&touched_atstart, 1);

	return;
}

static void
test_atexit_fp(unsigned threadno, void *user)
{
	(void)(threadno);

	if (user == user_data)
		__sync_add_and_fetch(&touched_exit, 1);

	return;
}

static void
output_callback(nmsg_message_t msg, void *user)
{
	(void)(msg);

	if (user == user_data)
		__sync_add_and_fetch(&num_received, 1);

	return;
}

/* A filter to permit only msg type NMSG_VENDOR_BASE_DNSQR_ID */
static nmsg_res
filter_callback(nmsg_message_t *msg, void *user, nmsg_filter_message_verdict *vres)
{

	if (user != user_data)
		return nmsg_res_failure;

	if (nmsg_message_get_msgtype(*msg) == NMSG_VENDOR_BASE_DNSQR_ID)
		*vres = nmsg_filter_message_verdict_DROP;
	else
		*vres = nmsg_filter_message_verdict_ACCEPT;

	__sync_add_and_fetch(&touched_filter, 1);

	return nmsg_res_success;
}

/* Just to test the filter policy. */
static nmsg_res
filter_callback2(nmsg_message_t *msg, void *user, nmsg_filter_message_verdict *vres)
{
	(void)(msg);

	if (user != user_data)
		return nmsg_res_failure;

	*vres = nmsg_filter_message_verdict_DECLINED;
	__sync_add_and_fetch(&touched_filter, 1);

	return nmsg_res_success;
}


/* XXX: Partially crippled.
 * Test custom nmsg io filter callbacks and output callbacks;
 * These are for close, at-start, and at-exit.
 * Test nmsg_io_set_count() [broken]. */
static int
test_io_filters(void)
{
	nmsg_io_t io;
	nmsg_output_t o;
	size_t run_cnt = 0;

	/*
	 * Loop #1: Verify all 10 nmsgs read normally.
	 * Loop #2: Set count to 7 and verify 7 msgs read normally.
	 * Loop #3: Apply first filter callback. It should drop all msgs of type !=
	 *          dnsqr, meaning that half (5) of the packets will be dropped.
	 * Loop #4: Apply second filter callback.
	 * Loop #5: Apply second filter callback with default filter policy of DROP.
	 */
	while (run_cnt < 5) {
		io = nmsg_io_init();
		check_return(io != NULL);

		/* Feed the nmsg io loop with 2 nmsg files that have 5 messages each. */
		check_return(nmsg_io_add_input_fname(io, SRCDIR "/tests/generic-tests/dnsqr2.nmsg", NULL) == nmsg_res_success);
		check_return(nmsg_io_add_input_fname(io, SRCDIR "/tests/generic-tests/packet.nmsg", NULL) == nmsg_res_success);

		/* Use an output callback for the output. */
		o = nmsg_output_open_callback(output_callback, user_data);
		check_return(o != NULL);
		check_return(nmsg_io_add_output(io, o, user_data) == nmsg_res_success);

		/* Reset the counters and set up all custom callbacks. */
		touched_atstart = touched_exit = touched_close = num_received = touched_filter = 0;
		nmsg_io_set_close_fp(io, test_close_fp);
		nmsg_io_set_atstart_fp(io, test_atstart_fp, user_data);
		nmsg_io_set_atexit_fp(io, test_atexit_fp, user_data);

		if (!run_cnt)
			nmsg_io_set_count(io, 10);
		else if (run_cnt == 1)
			nmsg_io_set_count(io, 7);
		else
			nmsg_io_set_count(io, 10);

		if (run_cnt == 2) {
			check(nmsg_io_add_filter(io, filter_callback, user_data) == nmsg_res_success);
		} else if (run_cnt == 3) {
			check(nmsg_io_add_filter(io, filter_callback2, user_data) == nmsg_res_success);
		} else if (run_cnt == 4) {
			check(nmsg_io_add_filter(io, filter_callback2, user_data) == nmsg_res_success);
			nmsg_io_set_filter_policy(io, nmsg_filter_message_verdict_DROP);
		}

		check(nmsg_io_loop(io) == nmsg_res_success);

		nmsg_io_destroy(&io);
		check(io == NULL);

		check(touched_atstart != 0);
		check(touched_exit == touched_atstart);
		check(touched_close >= touched_atstart);

		if (run_cnt == 2) {
			check(touched_filter == 10);
			check(num_received == 5);
		} else if (run_cnt == 3) {
			check(touched_filter == 10);
			check(num_received == 10);
		} else if (run_cnt == 4) {
			check(touched_filter == 10);
			check(num_received == 0);
		} else {
			check(touched_filter == 0);
			check(num_received == 10);
		}

		run_cnt++;
	}

	l_return_test_status();
}

/* Test nmsg_input_set_byte_rate(). */
static int
test_input_rate(void)
{
	struct timespec ts1, ts2;
	size_t all_rates[4] = { 0, 1800, 872, 520 };
	size_t n;

	/* Try this for a few different byte rates. */
	for (n = 0; n < (sizeof(all_rates) / sizeof(all_rates[0])); n++) {
		nmsg_input_t i;
		nmsg_message_t m;
		int fd, sfds[2];
		double d;

		/* We're simulating nmsg_stream_type_sock here. */
		check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, sfds) != -1);

		/* Read in our container which contains at least 5 payloads. */
		fd = open(SRCDIR "/tests/generic-tests/dnsqr2.nmsg", O_RDONLY);
		check_return(fd != -1);

		/* Open the simulated input and transmit the raw container to it. */
		i = nmsg_input_open_sock(sfds[0]);
		check_return(i != NULL);

		while (1) {
			char buf[1024];
			int nread;

			nread = read(fd, buf, sizeof(buf));

			if (nread <= 0)
				break;

			check_return(write(sfds[1], buf, nread) == nread);
		}

		nmsg_timespec_get(&ts1);

		/*
		 * Set the appropriate byte rate.
		 * Then serially read in the expected container - which
		 * consists of 5 payloads and a total of 1728 bytes.
		 */
		check_return(nmsg_input_set_byte_rate(i, all_rates[n]) == nmsg_res_success);
		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		nmsg_timespec_get(&ts2);
		nmsg_timespec_sub(&ts1, &ts2);
		d = nmsg_timespec_to_double(&ts2);

		/*
		 * Get the amount of time elapsed. For byte rate == 0, simply
		 * expect the transmission to have been near-simultaneous.
		 * The other byte rates have deliberately been chosen to result in
		 * an expected timeframe. For example, at a rate of 1,800 b/s we
		 * expect to read the entire container within a second. For 872 b/s,
		 * we expect the time elapsed to be at least 1 < n < 2.
		 */
		if (!n) {
			check(d < .05);
		} else {
			check((d > n - 1) && (d < n));
		}

		check(nmsg_input_close(&i) == nmsg_res_success);

		close(fd);
		close(sfds[1]);
	}

	l_return_test_status();
}

static size_t
count_chars(const char *str, unsigned char c)
{
	const char *bptr = str;
	size_t nfound = 0;

	while (bptr && *bptr) {
		bptr = strchr(bptr, c);

		if (!bptr)
			break;

		bptr++;
		nfound++;
	}

	return nfound;
}

/* Test the functioning of nmsg_output_set_endline(). */
static int
test_misc(void)
{
	nmsg_output_t o;
	nmsg_message_t m;
	char buf[4096];
	int fds[2], nread;
	size_t i, first_total = 0, first_nl = 0, first_q = 0;

	/*
	 * The test has two passes:
	 * The first pass checks the default endline of \n.
	 * The second pass checks a custom endline value.
	 */
	for (i = 0; i < 2; i++) {
		check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != -1);
		o = nmsg_output_open_pres(fds[1]);
		check_return(o != NULL);

		nmsg_output_set_buffered(o, true);

		return_if_error(make_message(&m));

		if (i)
			nmsg_output_set_endline(o, "Q");

		check_return(nmsg_output_write(o, m) == nmsg_res_success);
		nmsg_message_destroy(&m);
		check(nmsg_output_close(&o) == nmsg_res_success);

		memset(buf, 0, sizeof(buf));
		nread = recv(fds[0], buf, sizeof(buf), MSG_WAITALL);
		check_return(nread > 0);

		if (!i) {
			first_total = nread;
			first_nl = count_chars(buf, '\n');
			first_q = count_chars(buf, 'Q');
		} else {
			size_t this_nl, this_q;

			this_nl = count_chars(buf, '\n');
			this_q = count_chars(buf, 'Q');

			check((size_t)nread == first_total);
			check((first_nl - this_nl) == (this_q - first_q));
		}

		close(fds[0]);
	}

	l_return_test_status();
}


static nmsg_output_t forked_output = NULL;
static nmsg_message_t forked_message = NULL;
static int child_ready;

/* Write to an nmsg output with a slight delay. */
static void *
forked_write(void *arg)
{
	(void)(arg);

	child_ready = 1;

	if (usleep(100000) == -1)
		pthread_exit((void *)-1);

	if (nmsg_output_write(forked_output, forked_message) != nmsg_res_success)
		pthread_exit((void *)-1);

	pthread_exit(NULL);
}

/* Check to see if nmsg_input_set_blocking_io() works properly. */
static int
test_blocking(void)
{
	size_t n = 0;

	/*
	 * There are two sub-tests here.
	 * Both tests involve an nmsg output that feeds an nmsg input.
	 * By creating a thread to write to the output, we are able to introduce
	 * a slight delay between when the input tries to read data, and when that
	 * data is actually sent to it.
	 *
	 * The first subtest uses an nmsg input with blocking I/O. It should succeed.
	 * The second subtest turns off blocking. Because of the slight delay,
	 * it should fail.
	 */
	while (n < 2) {
		nmsg_input_t i;
		nmsg_message_t m;
		pthread_t p;
		int fds[2];
		void *ret;

		child_ready = 0;

		check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) != -1);

		forked_output = nmsg_output_open_sock(fds[1], 8192);
		check_return(forked_output != NULL);

		i = nmsg_input_open_sock(fds[0]);
		check_return(i != NULL);

		check_return(nmsg_input_set_blocking_io(i, !n) == nmsg_res_success);

		nmsg_output_set_buffered(forked_output, false);

		return_if_error(make_message(&forked_message));

		/* Create the writer thread but wait for it to be ready. */
		check_abort(pthread_create(&p, NULL, forked_write, NULL) == 0);

		while (!child_ready) {
			usleep(100);
		}

		/* We only expect to succeed if using blocking I/O. */
		if (!n) {
			check(nmsg_input_read(i, &m) == nmsg_res_success);
		} else {
			check(nmsg_input_read(i, &m) == nmsg_res_again);
		}

		/* Make sure the worker thread actually returned OK. */
		check_abort(pthread_join(p, &ret) == 0);
		check(ret == NULL);

		nmsg_message_destroy(&forked_message);
		check(nmsg_output_close(&forked_output) == nmsg_res_success);
		check(nmsg_input_close(&i) == nmsg_res_success);

		n++;
	}

	l_return_test_status();
}

int
main(void)
{
	check_abort(nmsg_init() == nmsg_res_success);

	check_explicit2_display_only(test_dummy() == 0, "test-io/ test_dummy");
	check_explicit2_display_only(test_multiplex() == 0, "test-io/ test_multiplex");
	check_explicit2_display_only(test_interval() == 0, "test-io/ test_interval");
	check_explicit2_display_only(test_sock() == 0, "test-io/ test_sock");
	check_explicit2_display_only(test_ozlib() == 0, "test-io/ test_ozlib");
	check_explicit2_display_only(test_io_filters() == 0, "test-io/ test_io_filters");
	check_explicit2_display_only(test_io_filters2() == 0, "test-io/ test_io_filters2");
	check_explicit2_display_only(test_io_sockspec() == 0, "test-io/ test_io_sockspec");
	check_explicit2_display_only(test_rate() == 0, "test-io/ test_rate");
	check_explicit2_display_only(test_input_rate() == 0, "test-io/ test_input_rate");
	check_explicit2_display_only(test_count() == 0, "test-io/ test_count");
	check_explicit2_display_only(test_blocking() == 0, "test-io/ test_blocking");
	check_explicit2_display_only(test_misc() == 0, "test-io/ test_misc");

        g_check_test_status(false);

}
