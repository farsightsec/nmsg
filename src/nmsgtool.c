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
#include "nmsgtool_buf.h"

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

	{ 'e', "endline",
		ARGV_CHAR_P,
		&ctx.endline,
		"endline",
		"continuation separator (def = \\\\\\n" },
	
	{ 't', "mtu",
		ARGV_INT,
		&ctx.mtu,
		"mtu",
		"MTU for datagram socket outputs" },

	{ 'r', "readnmsg",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_nmsg,
		"file",
		"read nmsg data from file" },

	{ 'f', "readpres",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_pres,
		"file",
		"read pres format data from file" },

	{ 'l', "readsock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_sock,
		"so",
		"add datagram socket input (addr/port)" },

	{ 'w', "writenmsg",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_nmsg,
		"file",
		"write nmsg data to file" },

	{ 'o', "writepres",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_pres,
		"file",
		"write pres format data to file" },

	{ 's', "writesock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_sock,
		"so[,r[,f]]",
		"add datagram socket output (addr/port)" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

/* Macros. */

/* Forward. */

static Nmsg__NmsgPayload *make_nmsg_payload(nmsgtool_ctx *, uint8_t *, size_t);
static nmsg_res do_pbuf2pbuf_loop(nmsgtool_ctx *);
static nmsg_res do_pbuf2pres_loop(nmsgtool_ctx *);
static nmsg_res do_pres2pbuf_loop(nmsgtool_ctx *);
static void *alloc_nmsg_payload(void *, size_t);
static void fail(nmsg_res res);
static void free_nmsg_payload(void *user, void *ptr);
static void mod_free_nmsg_payload(void *user, void *ptr);
static void nanotime(struct timespec *);
static void pbuf_callback(Nmsg__NmsgPayload *, void *);
static void pres_callback(Nmsg__NmsgPayload *, void *);
static void process_args(nmsgtool_ctx *);

/* Functions. */

int main(int argc, char **argv) {
	argv_process(args, argc, argv);
	ctx.ms = nmsg_pbmodset_open(NMSG_LIBDIR, ctx.debug);
	assert(ctx.ms != NULL);
	process_args(&ctx);
	ctx.fma = nmsg_fma_init("nmsgtool", 1, ctx.debug);
	ctx.ca.alloc = &alloc_nmsg_payload;
	ctx.ca.free = &free_nmsg_payload;
	ctx.ca.allocator_data = &ctx;
	ctx.modca.free = &mod_free_nmsg_payload;
	ctx.modca.allocator_data = &ctx;

	/*
	if (ctx.n_r_pres > 0 && ctx.n_w_nmsg > 0) {
		do_pres2pbuf_loop(&ctx);
	} else if (ctx.n_r_nmsg > 0 && ctx.n_w_pres > 0) {
		do_pbuf2pres_loop(&ctx);
	} else if (ctx.n_r_nmsg > 0 && ctx.n_w_nmsg > 0) {
		do_pbuf2pbuf_loop(&ctx);
	} else {
		usage(NULL);
	}
	*/

	nmsgtool_inputs_destroy(&ctx);
	nmsgtool_outputs_destroy(&ctx);
	nmsg_pbmodset_destroy(&ctx.ms);
	nmsg_fma_destroy(&ctx.fma);

	if (ctx.debug > 0)
		fprintf(stderr, "processed %" PRIu64 " messages\n",
			ctx.count_total);

	free(ctx.endline);
	return (0);
}

void usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

/* Private functions. */

static nmsg_res
do_pres2pbuf_loop(nmsgtool_ctx *c __attribute__((unused))) {
	return (nmsg_res_success);
}

#if 0
static nmsg_res
do_pres2pbuf_loop(nmsgtool_ctx *c) {
	FILE *fp;
	char line[1024];
	nmsg_pbmod mod;

	if (c->debug >= 1)
		fprintf(stderr, "%s: pres2pbuf loop starting\n", argv_program);

	fp = fdopen(c->fd_r_pres, "r");
	if (fp == NULL) {
		perror("fdopen");
		return (nmsg_res_failure);
	}
	mod = nmsg_pbmodset_lookup(c->ms, c->vendor, c->msgtype);
	assert(mod != NULL);
	while (fgets(line, sizeof(line), fp) != NULL) {
		nmsg_res res;
		size_t sz;
		uint8_t *pbuf;

		res = nmsg_pbmod_pres2pbuf(mod, line, &pbuf, &sz);
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
			res = nmsg_output_append(bufsink->buf, np, &c->modca);
			if (res != nmsg_res_success)
				fail(res);

			c->count_total += 1;
		} else if (res != nmsg_res_success) {
			fprintf(stderr, "pres2pbuf failed, res=%d\n", res);
		}
	}
	fclose(fp);
	return (nmsg_res_success);
}
#endif

static nmsg_res
do_pbuf2pbuf_loop(nmsgtool_ctx *c) {
	nmsg_buf rbuf;
	nmsg_res res;

	/*
	rbuf = nmsg_input_open(c->fd_r_nmsg);
	assert(rbuf != NULL);
	res = nmsg_input_loop(rbuf, -1, pbuf_callback, c);
	nmsg_buf_destroy(&rbuf);
	*/
	return (res);
}

static void
pbuf_callback(Nmsg__NmsgPayload *np, void *user) {
	Nmsg__NmsgPayload *npcopy;
	nmsg_res res;
	nmsgtool_ctx *c;
	struct nmsgtool_bufoutput *bufout;

	c = (nmsgtool_ctx *) user;
	npcopy = nmsg_payload_dup(np, &c->ca);
	if (npcopy == NULL)
		fail(nmsg_res_memfail);
	c->count_total += 1;
	bufout = ISC_LIST_HEAD(c->outputs);
	res = nmsg_output_append(bufout->buf, npcopy);
	if (res != nmsg_res_success)
		fail(res);
}

static nmsg_res
do_pbuf2pres_loop(nmsgtool_ctx *c) {
	nmsg_buf rbuf;
	nmsg_res res;

	/*
	//rbuf = nmsg_input_open(c->fd_r_nmsg);
	rbuf = ISC_LIST_HEAD(c->inputs)->buf;
	assert(rbuf != NULL);
	c->fp_w_pres = fdopen(c->fd_w_pres, "w");
	if (c->fp_w_pres == NULL) {
		perror("fdopen");
		return (nmsg_res_failure);
	}
	res = nmsg_input_loop(rbuf, -1, pres_callback, c);
	nmsg_buf_destroy(&rbuf);
	fclose(c->fp_w_pres);
	*/
	return (res);
}

static void
pres_callback(Nmsg__NmsgPayload *np, void *user) {
	char *pres;
	char when[32];
	nmsg_pbmod mod;
	nmsgtool_ctx *c;
	struct tm *tm;

	c = (nmsgtool_ctx *) user;
	c->count_total += 1;
	mod = nmsg_pbmodset_lookup(c->ms, np->vid, np->msgtype);
	tm = gmtime((time_t *) &np->time_sec);
	strftime(when, sizeof(when), "%Y-%m-%d %T", tm);
	nmsg_pbmod_pbuf2pres(mod, np, &pres, c->endline);
	fprintf(c->pres_output->fp, "[%zd] %s.%09u [%s %s] %s%s",
		np->has_payload ? np->payload.len : 0,
		when, np->time_nsec,
		nmsg_pbmodset_vid2vname(c->ms, np->vid),
		nmsg_pbmodset_msgtype2mname(c->ms, np->vid, np->msgtype),
		c->endline,
		pres);
	nmsg_pbmod_free_pres(mod, &pres);
}

static void
process_args(nmsgtool_ctx *c) {
	int i;

	if (c->help)
		usage(NULL);
	if (c->endline == NULL)
		c->endline = strdup("\\\n");
	if (c->mtu == 0)
		c->mtu = nmsg_wbufsize_max;
	if (c->vname) {
		if (c->mname == NULL)
			usage("-V requires -T");
		c->vendor = nmsg_pbmodset_vname2vid(c->ms, c->vname);
		if (c->vendor == 0)
			usage("invalid vendor ID");
		if (c->debug > 0)
			fprintf(stderr, "%s: vendor = %s\n", argv_program,
				c->vname);
	}
	if (c->mname) {
		if (c->vname == NULL)
			usage("-T requires -V");
		c->msgtype = nmsg_pbmodset_mname2msgtype(c->ms, c->vendor,
							 c->mname);
		if (c->msgtype == 0)
			usage("invalid message type");
		if (c->debug > 0)
			fprintf(stderr, "%s: msgtype = %s\n", argv_program,
				c->mname);
	}

	/* I/O parameters */

	/* nmsg socket inputs */
	if (ARGV_ARRAY_COUNT(c->r_sock) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->r_sock); i++)
			nmsgtool_inputs_add_sock(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->r_sock, char *, i));
	/* nmsg socket outputs */
	if (ARGV_ARRAY_COUNT(c->w_sock) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_sock); i++)
			nmsgtool_outputs_add_sock(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->w_sock, char *, i));
	/* nmsg file inputs */
	if (ARGV_ARRAY_COUNT(c->r_nmsg) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->r_nmsg); i++)
			nmsgtool_inputs_add_file(&ctx, 
				*ARGV_ARRAY_ENTRY_P(c->r_nmsg, char *, i));
	/* nmsg file outputs */
	if (ARGV_ARRAY_COUNT(c->w_nmsg) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_nmsg); i++)
			nmsgtool_outputs_add_file(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->w_nmsg, char *, i));
	/* pres file inputs */
	if (ARGV_ARRAY_COUNT(c->r_pres) > 0) {
		if (c->vname == NULL || c->mname == NULL)
			usage("reading presentation data requires -V, -T");
		/* XXX */
	}
	/* pres file output */
	if (ARGV_ARRAY_COUNT(c->w_pres) > 0) {
		if (ARGV_ARRAY_COUNT(c->w_pres) > 1)
			usage("specify exactly one pres format output");
		if (ARGV_ARRAY_COUNT(c->w_nmsg) > 0)
			usage("specify nmsg or pres format output, not both");
		/* XXX */
	}

	/* validation */

	if (c->n_inputs == 0)
		usage("no data sources specified");
	if (c->n_outputs == 0)
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

static void *
alloc_nmsg_payload(void *user, size_t size) {
	nmsgtool_ctx *c = (nmsgtool_ctx *) user;
	void *ptr = nmsg_fma_alloc(c->fma, size);
	return (ptr);
}

static void
free_nmsg_payload(void *user, void *ptr) {
	nmsgtool_ctx *c = (nmsgtool_ctx *) user;
	Nmsg__NmsgPayload *np = (Nmsg__NmsgPayload *) ptr;
	if (np->has_payload)
		nmsg_fma_free(c->fma, np->payload.data);
	nmsg_fma_free(c->fma, ptr);
}

static void
mod_free_nmsg_payload(void *user, void *ptr) {
	nmsgtool_ctx *c = (nmsgtool_ctx *) user;
	Nmsg__NmsgPayload *np = (Nmsg__NmsgPayload *) ptr;
	nmsg_pbmod mod = nmsg_pbmodset_lookup(c->ms, np->vid, np->msgtype);

	nmsg_pbmod_free_pbuf(mod, np->payload.data);
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

static void
fail(nmsg_res res) {
	fprintf(stderr, "%s: failure: res=%d\n", argv_program, res);
	exit(1);
}
