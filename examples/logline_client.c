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

#define _XOPEN_SOURCE
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
#include <nmsg/isc/nmsgpb_isc_logline.h>

/* Macros. */

#define MODULE_DIR	"/usr/local/lib/nmsg"

#define DST_ADDRESS	"127.0.0.1"
#define DST_PORT	8430
#define DST_BUFSZ	1280

#define LINESZ		1024

/* Data structures. */

struct ctx_nmsg {
	nmsg_output_t output;
	nmsg_pbmod_t mod;
	nmsg_pbmodset_t ms;
	void *clos_mod;
};

/* Forward. */

static void
setup_nmsg(struct ctx_nmsg *ctx, const char *ip, uint16_t port, size_t bufsz,
	   const char *module_dir, unsigned vid, unsigned msgtype);

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
	   const char *module_dir, unsigned vid, unsigned msgtype)
{
	struct sockaddr_in nmsg_sockaddr;
	nmsg_res res;
	int nmsg_sock;

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

	/* load modules */
	ctx->ms = nmsg_pbmodset_init(module_dir, 0);
	if (ctx->ms == NULL) {
		fprintf(stderr, "nmsg_pbmodset_init() failed\n");
		exit(1);
	}

	/* open handle to the module */
	ctx->mod = nmsg_pbmodset_lookup(ctx->ms, vid, msgtype);
	if (ctx->mod == NULL) {
		fprintf(stderr, "nmsg_pbmodset_lookup() failed\n");
		exit(1);
	}

	/* initialize module */
	res = nmsg_pbmod_init(ctx->mod, &ctx->clos_mod);
	if (res != nmsg_res_success)
		exit(res);
}

static void
shutdown_nmsg(struct ctx_nmsg *ctx) {
	/* finalize module */
	nmsg_pbmod_fini(ctx->mod, &ctx->clos_mod);

	/* close nmsg output */
	nmsg_output_close(&ctx->output);

	/* unload modules */
	nmsg_pbmodset_destroy(&ctx->ms);
}

static void
send_nmsg_logline_payload(struct ctx_nmsg *ctx, struct timespec *ts,
			  char *category, char *message)
{
	Nmsg__Isc__LogLine logline;
	Nmsg__NmsgPayload *np;
	nmsg_res res;

	memset(&logline, 0, sizeof(logline));
	res = nmsg_pbmod_message_init(ctx->mod, &logline);
	assert(res == nmsg_res_success);

	if (category != NULL) {
		logline.category.data = (uint8_t *) category;
		logline.category.len = strlen(category) + 1;
		logline.has_category = true;
	}

	if (message != NULL) {
		logline.message.data = (uint8_t *) message;
		logline.message.len = strlen(message) + 1;
		logline.has_message = true;
	}

	np = nmsg_payload_from_message(&logline, NMSG_VENDOR_ISC_ID,
				       MSGTYPE_LOGLINE_ID, ts);
	if (np != NULL)
		nmsg_output_write(ctx->output, np);
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
	char line[LINESZ];
	char *category, *message;
	struct timespec ts;

	log = fopen(fname, "r");
	if (log == NULL) {
		perror("fopen");
		return;
	}

	while (fgets(line, sizeof(line), log) != NULL) {
		if (parse_syslog_line(line, &ts, &category, &message) == true) {
			send_nmsg_logline_payload(ctx, &ts, category, message);
			free(category);
			free(message);
		}
	}
}

int main(int argc, char **argv) {
	struct ctx_nmsg ctx;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <syslog file>\n", argv[0]);
		return (1);
	}

	setup_nmsg(&ctx, DST_ADDRESS, DST_PORT, DST_BUFSZ, MODULE_DIR,
		   NMSG_VENDOR_ISC_ID, MSGTYPE_LOGLINE_ID);

	parse_syslog_file_and_send(&ctx, argv[1]);

	shutdown_nmsg(&ctx);

	return (0);
}
