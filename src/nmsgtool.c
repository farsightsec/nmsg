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
#include <errno.h>
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

static argv_t args[] = {
	{ 'h',	"help",
		ARGV_BOOL,
		&ctx.help,
		NULL,
		"display help text and exit" },

	{ 'd',	"debug",
		ARGV_INCR,
		&ctx.debug,
		NULL,
		"increment debugging level" },

	{ 'V', "vendor",
		ARGV_CHAR_P,
		&ctx.vname,
		"vendor",
		"vendor" },

	{ 'T', "msgtype",
		ARGV_CHAR_P,
		&ctx.mname,
		"msgtype",
		"message type" },

	{ 'f', "readpres",
		ARGV_CHAR_P,
		&ctx.r_pres,
		"file",
		"read pres format data from file" },

	{ 'o', "writepres",
		ARGV_CHAR_P,
		&ctx.w_pres,
		"file",
		"write pres format data to file" },

	{ 'r', "readnmsg",
		ARGV_CHAR_P,
		&ctx.r_nmsg,
		"file",
		"read nmsg data from file" },

	{ 'w', "writenmsg",
		ARGV_CHAR_P,
		&ctx.w_nmsg,
		"file",
		"write nmsg data to file" },

	{ 's', "socksink",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.socksinks,
		"so[,r[,f]]",
		"add datagram socket output" },

	{ 'e', "endline",
		ARGV_CHAR_P,
		&ctx.endline,
		"endline",
		"continuation separator (def = \\\\\\n\\t" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

/* Macros. */

/* Forward. */

static Nmsg__NmsgPayload *make_nmsg_payload(nmsgtool_ctx *, uint8_t *, size_t);
static int open_rfile(nmsgtool_ctx *, const char *);
static int open_wfile(nmsgtool_ctx *, const char *);
static nmsg_res do_pbuf2pres_loop(nmsgtool_ctx *);
static nmsg_res do_pres2pbuf_loop(nmsgtool_ctx *);
static void free_nmsg_payload(void *user, void *ptr);
static void nanotime(struct timespec *);
static void pres_callback(Nmsg__NmsgPayload *, void *);
static void process_args(nmsgtool_ctx *);

/* Functions. */

int main(int argc, char **argv) {
	argv_process(args, argc, argv);
	ctx.ms = nmsg_pbmodset_load(NMSG_LIBDIR, ctx.debug);
	assert(ctx.ms != NULL);
	process_args(&ctx);
	ctx.fma = nmsg_fma_init("nmsgtool", 1, ctx.debug);
	ctx.ca.free = &free_nmsg_payload;
	ctx.ca.allocator_data = &ctx;

	if (ctx.n_r_pres > 0 && ctx.n_w_nmsg > 0)
		do_pres2pbuf_loop(&ctx);
	else if (ctx.n_r_nmsg > 0 && ctx.n_w_pres > 0)
		do_pbuf2pres_loop(&ctx);

	socksink_destroy(&ctx);
	nmsg_pbmodset_destroy(&ctx.ms);
	nmsg_fma_destroy(&ctx.fma);

	if (ctx.debug > 0)
		fprintf(stderr, "processed %" PRIu64 " messages\n",
			ctx.count_total);

	return (0);
}

void usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

/* Private functions. */

static nmsg_res
do_pres2pbuf_loop(nmsgtool_ctx *c) {
	FILE *fp;
	char line[1024];

	if (c->debug >= 1)
		fprintf(stderr, "%s: pres2pbuf loop starting\n", argv_program);

	fp = fdopen(c->fd_r_pres, "r");
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

			c->count_total += 1;
		} else if (res != nmsg_res_success) {
			fprintf(stderr, "pres2pbuf failed, res=%d\n", res);
		}
	}
	fclose(fp);
	return (nmsg_res_success);
}

static nmsg_res
do_pbuf2pres_loop(nmsgtool_ctx *c) {
	nmsg_buf rbuf;

	rbuf = nmsg_input_open_fd(c->fd_r_nmsg);
	c->fp_w_pres = fdopen(c->fd_w_pres, "w");
	if (c->fp_w_pres == NULL) {
		perror("fdopen");
		return (nmsg_res_failure);
	}
	return (nmsg_loop(rbuf, -1, pres_callback, c));
}

static void
pres_callback(Nmsg__NmsgPayload *np, void *user) {
	char when[32];
	nmsgtool_ctx *c = (nmsgtool_ctx *) user;
	struct tm *tm;

	c->count_total += 1;

	tm = gmtime((time_t *) &np->time_sec);
	strftime(when, sizeof(when), "%Y-%m-%d %T", tm);
	fprintf(c->fp_w_pres, "[%zd %s] %s.%09u [%s %s]\n",
		np->has_payload ? np->payload.len : 0,
		c->r_nmsg,
		when, np->time_nsec,
		nmsg_vid2vname(c->ms, np->vid),
		nmsg_msgtype2mname(c->ms, np->vid, np->msgtype));
}

static void
process_args(nmsgtool_ctx *c) {
	if (c->help)
		usage(NULL);
	if (c->vname) {
		c->vendor = nmsg_vname2vid(c->ms, c->vname);
		if (c->vendor == 0)
			usage("invalid vendor ID");
		if (c->debug > 0)
			fprintf(stderr, "nmsgtool: vendor = %s\n", c->vname);
	}
	if (c->vname && c->mname) {
		c->msgtype = nmsg_mname2msgtype(c->ms, c->vendor, c->mname);
		if (c->msgtype == 0)
			usage("invalid message type");
		if (c->debug > 0)
			fprintf(stderr, "nmsgtool: msgtype = %s\n", c->mname);
	}
	if (ARGV_ARRAY_COUNT(c->socksinks) > 0) {
		int i;

		for (i = 0; i < ARGV_ARRAY_COUNT(c->socksinks); i++) {
			char *ss = *ARGV_ARRAY_ENTRY_P(c->socksinks, char *, i);
			if (c->debug > 0)
				fprintf(stderr, "nmsgtool: sockout = %s\n", ss);
			socksink_init(&ctx, ss);
		}
	}

	if (c->r_pres && (c->vname == NULL || c->mname == NULL))
		usage("reading presentation data requires specifying -V, -T");

	/* XXX handle multiple input/output files */
	if (c->r_nmsg) {
		c->n_r_nmsg = 1;
		c->fd_r_nmsg = open_rfile(c, c->r_nmsg);
	}
	if (c->r_pres) {
		c->n_r_pres = 1;
		c->fd_r_pres = open_rfile(c, c->r_pres);
	}
	if (c->w_nmsg) {
		nmsgtool_bufsink *bufsink;

		c->n_w_nmsg = 1;
		c->fd_w_nmsg = open_wfile(c, c->w_nmsg);

		bufsink = calloc(1, sizeof(*bufsink));
		assert(bufsink != NULL);
		ISC_LINK_INIT(bufsink, link);

		bufsink->buf = nmsg_output_open_fd(c->fd_w_nmsg,
						   nmsg_wbufsize_max);
		ISC_LIST_APPEND(c->bufsinks, bufsink, link);
	}
	if (c->w_pres) {
		c->n_w_pres = 1;
		c->fd_w_pres = open_wfile(c, c->w_pres);
	}

	/* XXX support more combinations below */
	if (c->n_r_nmsg + c->n_r_pres == 0)
		usage("no data sources specified");
	if (c->n_w_nmsg + c->n_w_pres == 0)
		usage("no data sinks specified");
	if (c->n_r_nmsg > 0 && c->n_r_pres > 0)
		usage("specify either nmsg or pres format outputs, not both");
	if (c->n_w_nmsg > 0 && c->n_w_pres > 0)
		usage("specify either nmsg or pres format inputs, not both");

	if (c->n_r_pres > 1)
		usage("specify exactly one pres format input");
	if (c->n_w_pres > 1)
		usage("specify exactly one pres format output");
	if (c->n_r_pres == 1 && c->n_w_pres == 1 &&
	    c->n_r_nmsg == 0 && c->n_w_nmsg == 0)
	{
		usage("see cat(1)");
	}
}

static int
open_rfile(nmsgtool_ctx *c, const char *fname) {
	int fd;
	if (strcmp("-", fname) == 0)
		fd = STDIN_FILENO;
	else {
		fd = open(fname, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "%s: unable to open %s for reading: "
				"%s\n", argv_program, fname, strerror(errno));
			exit(1);
		}
	}
	if (c->debug)
		fprintf(stderr, "%s: opened %s for reading\n", argv_program,
			fname);
	return (fd);
}

static int
open_wfile(nmsgtool_ctx *c, const char *fname) {
	int fd;
	if (strcmp("-", fname) == 0)
		fd = STDOUT_FILENO;
	else {
		fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd == -1) {
			fprintf(stderr, "%s: unable to open %s for writing: "
				"%s\n", argv_program, fname, strerror(errno));
			exit(1);
		}
	}
	if (c->debug)
		fprintf(stderr, "%s: opened %s for writing\n", argv_program,
			fname);
	return (fd);
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
