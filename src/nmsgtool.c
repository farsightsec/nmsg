/* nmsgtool.c - libnmsg tool shell */

/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#include "nmsg_port.h"

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#include <nmsg.h>
#include "config.h"

#include "nmsgtool.h"
#include "nmsgtool_sock.h"

/* Globals. */

static nmsgtool_ctx ctx;
static uint64_t count_total;

static argv_t args[] = {
	{ 'h', "help", ARGV_BOOL, &ctx.help,
		NULL, "display help text and exit" },

	{ 'd', "debug", ARGV_INCR, &ctx.debug,
		NULL, "increment debugging level" },

	{ 'V', "vendor", ARGV_CHAR_P, &ctx.vname,
		"vendor", "vendor" },

	{ 'T', "msgtype", ARGV_CHAR_P, &ctx.mname,
		"msgtype", "message type" },
	
	{ 'r', "presfile", ARGV_CHAR_P, &ctx.presfile,
		"presfile", "read pres format data from file" },

	{ 's', "socksink", ARGV_CHAR_P | ARGV_FLAG_ARRAY, &ctx.socksinks,
		"socksink", "add datagram socket output" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

/* Macros. */

/* Forward. */

static Nmsg__NmsgPayload *make_nmsg_payload(nmsgtool_ctx *, uint8_t *, size_t);
static nmsg_res do_pres_loop(nmsgtool_ctx *);
static void free_nmsg_payload(void *user, void *ptr);
static void nanotime(struct timespec *);
static void process_args(void);

/* Functions. */

int main(int argc, char **argv) {
	argv_process(args, argc, argv);

	ctx.ms = nmsg_pbmodset_load(NMSG_LIBDIR, ctx.debug);
	process_args();
	ctx.fma = nmsg_fma_init("nmsgtool", 1, ctx.debug);
	ctx.ca.free = &free_nmsg_payload;
	ctx.ca.allocator_data = &ctx;
	if (ctx.npres > 0 && ctx.nsinks > 0)
		do_pres_loop(&ctx);
	if (ctx.ms != NULL)
		nmsg_pbmodset_destroy(&ctx.ms);
	socksink_destroy(&ctx);
	nmsg_fma_destroy(&ctx.fma);
	close(ctx.pres_fd);

	if (ctx.debug > 0)
		fprintf(stderr, "processed %" PRIu64 " messages\n", count_total);
	return (0);
}

void usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

/* Private functions. */

static nmsg_res
do_pres_loop(nmsgtool_ctx *c) {
	FILE *fp;
	char line[1024];

	fp = fdopen(c->pres_fd, "r");
	if (fp == NULL) {
		perror("fdopen");
		return (nmsg_res_failure);
	}
	while (fgets(line, sizeof(line), fp) != NULL) {
		nmsg_res res;
		size_t sz;
		uint8_t *pbuf;

		res = nmsg_pres2pbuf(c->ms, c->vendor, c->msgtype, line,
				     &pbuf, &sz);
		if (res == nmsg_res_pbuf_ready) {
			Nmsg__NmsgPayload *np;
			struct nmsgtool_bufsink *bufsink;

			np = make_nmsg_payload(c, pbuf, sz);

/*
			for (bufsink = ISC_LIST_HEAD(c->bufsinks);
			     bufsink != NULL;
			     bufsink = ISC_LIST_NEXT(bufsink, link))
			{
			}
*/
			bufsink = ISC_LIST_HEAD(c->bufsinks);
			res = nmsg_output_append(bufsink->buf, np, &c->ca);
			if (res != nmsg_res_success) {
				fprintf(stderr, "res=%d\n", res);
				exit(1);
			}

			count_total += 1;

		}
	}
	fclose(fp);
	return (nmsg_res_success);
}

static void
process_args(void) {
	if (ctx.help)
		usage(NULL);
	if (ctx.vname) {
		ctx.vendor = nmsg_vname2vid(ctx.ms, ctx.vname);
		if (ctx.vendor == 0)
			usage("invalid vendor ID");
		if (ctx.debug > 0)
			fprintf(stderr, "nmsgtool: vendor = %s\n", ctx.vname);
	}
	if (ctx.vname && ctx.mname) {
		ctx.msgtype = nmsg_mname2msgtype(ctx.ms, ctx.vendor, ctx.mname);
		if (ctx.msgtype == 0)
			usage("invalid message type");
		if (ctx.debug > 0)
			fprintf(stderr, "nmsgtool: msgtype = %s\n", ctx.mname);
	}
	if (ARGV_ARRAY_COUNT(ctx.socksinks) > 0) {
		int i;

		for (i = 0; i < ARGV_ARRAY_COUNT(ctx.socksinks); i++) {
			char *ss = *ARGV_ARRAY_ENTRY_P(ctx.socksinks, char *, i);
			if (ctx.debug > 0)
				fprintf(stderr, "nmsgtool: sockout = %s\n", ss);
			socksink_init(&ctx, ss);
		}
	}
	if (ctx.presfile) {
		/* XXX handle multiple pres files */
		ctx.npres = 1;
		if (strcmp("-", ctx.presfile) == 0)
			ctx.pres_fd = STDIN_FILENO;
		else {
			ctx.pres_fd = open(ctx.presfile, O_RDONLY);
			if (ctx.pres_fd == -1) {
				perror("open");
				exit(1);
			}
			if (ctx.debug > 0)
				fprintf(stderr, "nmsgtool: opened %s\n",
					ctx.presfile);
		}
	}
	if (ctx.nsinks == 0)
		usage("no data sinks specified");
}

static Nmsg__NmsgPayload *
make_nmsg_payload(nmsgtool_ctx *c, uint8_t *pbuf, size_t sz) {
	Nmsg__NmsgPayload *np;
	struct timespec now;

	nanotime(&now);
	np = nmsg_fma_alloc(c->fma, sizeof(*np));
	if (np == NULL)
		return (NULL);
	np->base.descriptor = &nmsg__nmsg_payload__descriptor;
	np->vid = c->vendor;
	np->msgtype = c->msgtype;
	np->time_sec = now.tv_sec;
	np->time_nsec = now.tv_nsec;
	np->has_payload = 1;
	np->payload.len = sz;
	np->payload.data = pbuf;

	return (np);
}

static void
free_nmsg_payload(void *user, void *ptr) {
	nmsgtool_ctx *c = (nmsgtool_ctx *) user;
	Nmsg__NmsgPayload *np = (Nmsg__NmsgPayload *) ptr;

	nmsg_free_pbuf(c->ms, c->vendor, c->msgtype, np->payload.data);
	nmsg_fma_free(c->fma, np);
}

static void
nanotime(struct timespec *now) {
#ifdef HAVE_CLOCK_GETTIME
	(void) clock_gettime(CLOCK_REALTIME, now);
#else
	struct timeval tv;
	(void) gettimeofday(&tv, NULL);
	now->tv_sec = tv.tv_sec;
	now->tv_nsec = tv.tv_usec * 1000;
#endif
}
