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

	{ 'R', "rate",
		ARGV_INT,
		&ctx.rate,
		"rate",
		"transmit rate" },

	{ 'F', "freq",
		ARGV_INT,
		&ctx.freq,
		"freq",
		"transmit scheduling frequency (default 100)" },

	{ 'M', "mirror",
		ARGV_BOOL,
		&ctx.mirror,
		NULL,
		"mirror across data outputs" },

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

static void process_args(nmsgtool_ctx *);

/* Functions. */

int main(int argc, char **argv) {
	argv_process(args, argc, argv);
	ctx.ms = nmsg_pbmodset_open(NMSG_LIBDIR, ctx.debug);
	assert(ctx.ms != NULL);
	ctx.io = nmsg_io_init(ctx.ms);
	assert(ctx.io != NULL);
	process_args(&ctx);
	nmsg_io_set_debug(ctx.io, ctx.debug);
	nmsg_io_set_endline(ctx.io, ctx.endline);
	nmsg_io_set_freq(ctx.io, ctx.freq);
	nmsg_io_set_rate(ctx.io, ctx.rate);
	if (ctx.mirror == true)
		nmsg_io_set_output_mode(ctx.io, nmsg_io_output_mode_mirror);
	ctx.fma = nmsg_fma_init("nmsgtool", 1, ctx.debug);

	nmsg_io_loop(ctx.io);
	nmsg_io_destroy(&ctx.io);
	nmsg_pbmodset_destroy(&ctx.ms);
	nmsg_fma_destroy(&ctx.fma);

	free(ctx.endline);
	argv_cleanup(args);
	return (0);
}

void usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

/* Private functions. */

static void
process_args(nmsgtool_ctx *c) {
	int i;

	if (c->help)
		usage(NULL);
	if (c->endline == NULL)
		c->endline = strdup("\\\n");
	if (c->mtu == 0)
		c->mtu = nmsg_wbufsize_jumbo;
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
			nmsgtool_add_sock_input(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->r_sock, char *, i));
	/* nmsg socket outputs */
	if (ARGV_ARRAY_COUNT(c->w_sock) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_sock); i++)
			nmsgtool_add_sock_output(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->w_sock, char *, i));
	/* nmsg file inputs */
	if (ARGV_ARRAY_COUNT(c->r_nmsg) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->r_nmsg); i++)
			nmsgtool_add_file_input(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->r_nmsg, char *, i));
	/* nmsg file outputs */
	if (ARGV_ARRAY_COUNT(c->w_nmsg) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_nmsg); i++)
			nmsgtool_add_file_output(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->w_nmsg, char *, i));
	/* pres file inputs */
	if (ARGV_ARRAY_COUNT(c->r_pres) > 0) {
		nmsg_pbmod mod;
		if (c->vname == NULL || c->mname == NULL)
			usage("reading presentation data requires -V, -T");
		mod = nmsg_pbmodset_lookup(c->ms, c->vendor, c->msgtype);
		if (mod == NULL)
			usage("unknown pbmod");
		for (i = 0; i < ARGV_ARRAY_COUNT(c->r_pres); i++)
			nmsgtool_add_pres_input(&ctx, mod,
				*ARGV_ARRAY_ENTRY_P(c->r_pres, char *, i));
	}
	/* pres file output */
	if (ARGV_ARRAY_COUNT(c->w_pres) > 0) {
		nmsg_pbmod mod;
		mod = nmsg_pbmodset_lookup(c->ms, c->vendor, c->msgtype);
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_pres); i++)
			nmsgtool_add_pres_output(&ctx, mod,
				*ARGV_ARRAY_ENTRY_P(c->w_pres, char *, i));
	}

	/* validation */

	if (c->n_inputs == 0)
		usage("no data sources specified");
	if (c->n_outputs == 0)
		usage("no data sinks specified");
}
