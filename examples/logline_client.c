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

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <nmsg.h>
#include <nmsg/isc/defs.h>
#include <ustr.h>

/* Macros. */

#define DST_ADDRESS	"127.0.0.1"
#define DST_PORT	8430
#define DST_BUFSZ	1280

#define nmsf(a,b,c,d,e) do { \
	nmsg_res _res; \
	_res = nmsg_message_set_field(a,b,c,(uint8_t *) d,e); \
	assert(_res == nmsg_res_success); \
} while (0)

/* Data structures. */

struct ctx_nmsg {
	nmsg_output_t output;
	nmsg_msgmod_t mod;
	void *clos_mod;
};

/* Forward. */

static void
setup_nmsg(struct ctx_nmsg *ctx, const char *ip, uint16_t port, size_t bufsz,
	   unsigned vid, unsigned msgtype);

static void
shutdown_nmsg(struct ctx_nmsg *ctx);

static void
send_nmsg_logline_payload(struct ctx_nmsg *ctx, struct timespec *ts,
			  char *category, char *message);

static bool
parse_syslog_line(const char *line, struct timespec *ts,
		  char **category, char **message);

static void
parse_syslog_file_and_send(struct ctx_nmsg *ctx, const char *fname);

/* Functions. */

static void
setup_nmsg(struct ctx_nmsg *ctx, const char *ip, uint16_t port, size_t bufsz,
	   unsigned vid, unsigned msgtype)
{
	struct sockaddr_in nmsg_sockaddr;
	nmsg_res res;
	int nmsg_sock;

	/* initialize libnmsg */
	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "unable to initialize libnmsg\n");
		exit(1);
	}

	/* set dst address / port */
	if (inet_pton(AF_INET, ip, &nmsg_sockaddr.sin_addr)) {
		nmsg_sockaddr.sin_family = AF_INET;
		nmsg_sockaddr.sin_port = htons(port);
	} else {
		perror("inet_pton");
		exit(1);
	}

	/* open socket */
	nmsg_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (nmsg_sock < 0) {
		perror("socket");
		exit(1);
	}

	/* connect socket */
	if (connect(nmsg_sock, (struct sockaddr *) &nmsg_sockaddr,
		    sizeof(nmsg_sockaddr)) < 0)
	{
		perror("connect");
		exit(1);
	}

	/* create nmsg output */
	ctx->output = nmsg_output_open_sock(nmsg_sock, bufsz);
	if (ctx->output == NULL) {
		fprintf(stderr, "nmsg_output_open_sock() failed\n");
		exit(1);
	}
	nmsg_output_set_buffered(ctx->output, false);

	/* open handle to the module */
	ctx->mod = nmsg_msgmod_lookup(vid, msgtype);
	if (ctx->mod == NULL) {
		fprintf(stderr, "nmsg_msgmodset_lookup() failed\n");
		exit(1);
	}

	/* initialize module */
	res = nmsg_msgmod_init(ctx->mod, &ctx->clos_mod);
	if (res != nmsg_res_success)
		exit(res);
}

static void
shutdown_nmsg(struct ctx_nmsg *ctx) {
	/* finalize module */
	nmsg_msgmod_fini(ctx->mod, &ctx->clos_mod);

	/* close nmsg output */
	nmsg_output_close(&ctx->output);
}

static void
send_nmsg_logline_payload(struct ctx_nmsg *ctx, struct timespec *ts,
			  char *category, char *message)
{
	nmsg_message_t msg;

	msg = nmsg_message_init(ctx->mod);
	assert(msg != NULL);

	nmsg_message_set_time(msg, ts);

	if (category != NULL)
		nmsf(msg, "category", 0, category, strlen(category) + 1);

	if (message != NULL)
		nmsf(msg, "message", 0, message, strlen(message) + 1);

	nmsg_output_write(ctx->output, msg);
	nmsg_message_destroy(&msg);
}

static bool
parse_syslog_line(const char *line, struct timespec *ts,
		  char **category, char **message)
{
	char *tmp;
	struct tm tm;
	struct timeval tv;
	int year;

	if (gettimeofday(&tv, NULL) != 0)
		return (false);

	if (gmtime_r(&tv.tv_sec, &tm) == NULL)
		return (false);
	year = tm.tm_year;

	if (strptime(line, "%b %d %H:%M:%S", &tm) == NULL)
		return (false);
	tm.tm_year = year;
	tm.tm_isdst = -1;

	if ((ts->tv_sec = mktime(&tm)) == -1)
		return (false);
	ts->tv_nsec = 0;

	if (strlen(line) < 16)
		return (false);

	*category = strdup(line + 16); /* trim timestamp */
	*message = strdup(strchr(*category, ':') + 2); /* trim category */

	tmp = strchr(*category, ':'); /* truncate category at colon */
	tmp[0] = '\0';

	tmp = strchr(*message, '\n'); /* truncate message at newline */
	tmp[0] = '\0';

	return (true);
}

static void
parse_syslog_file_and_send(struct ctx_nmsg *ctx, const char *fname) {
	FILE *log;
	Ustr *line;
	char *category, *message;
	struct timespec ts;

	line = ustr_dup_empty();

	log = fopen(fname, "r");
	if (log == NULL) {
		perror("fopen");
		return;
	}

	while (ustr_io_getline(&line, log)) {
		if (parse_syslog_line(ustr_cstr(line), &ts, &category, &message) == true) {
			send_nmsg_logline_payload(ctx, &ts, category, message);
			free(category);
			free(message);
			ustr_set_empty(&line);
		}
	}

	fclose(log);
}

int main(int argc, char **argv) {
	struct ctx_nmsg ctx;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <syslog file>\n", argv[0]);
		return (1);
	}

	setup_nmsg(&ctx, DST_ADDRESS, DST_PORT, DST_BUFSZ,
		   NMSG_VENDOR_ISC_ID, NMSG_VENDOR_ISC_LOGLINE_ID);

	parse_syslog_file_and_send(&ctx, argv[1]);

	shutdown_nmsg(&ctx);

	return (0);
}
