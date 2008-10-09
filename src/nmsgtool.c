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
#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nmsg.h>
#include "config.h"

#include "nmsgtool.h"
#include "nmsgtool_sock.h"

/* Globals. */

static nmsgtool_ctx ctx;

static argv_t args[] = {
	{ 'h', "help", ARGV_BOOL, &ctx.help,
		NULL, "display help text and exit" },

	{ 'd', "debug", ARGV_INCR, &ctx.debug,
		NULL, "increment debugging level" },

	{ 'V', "vendor", ARGV_CHAR_P, &ctx.vname,
		"vendor", "vendor" },

	{ 'T', "msgtype", ARGV_CHAR_P, &ctx.mname,
		"msgtype", "message type" },
	
	{ 's', "socksink", ARGV_CHAR_P | ARGV_FLAG_ARRAY, &ctx.socksinks,
		"socksink", "add datagram socket output" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

/* Macros. */

/* Forward. */

static void process_args(void);

/* Functions. */

int main(int argc, char **argv) {
	argv_process(args, argc, argv);

	ctx.ms = nmsg_pbmodset_load(NMSG_LIBDIR, ctx.debug);
	process_args();

	if (ctx.ms != NULL)
		nmsg_pbmodset_destroy(&ctx.ms);
	return (0);
}

void usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

/* Private functions. */

static void process_args(void) {
	if (ctx.help)
		usage(NULL);
	if (ctx.vname) {
		ctx.vendor = nmsg_vname2vid(ctx.ms, ctx.vname);
		if (ctx.vendor == 0)
			usage("invalid vendor ID");
		if (ctx.debug > 0)
			fprintf(stderr, "nmsgtool: vendor = %s\n", ctx.vname);
	}
	if (ctx.mname) {
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
			setup_socksink(&ctx, ss);
		}
	}
}
