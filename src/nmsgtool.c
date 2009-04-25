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

#include "nmsg_port.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nmsg.h>

#include "nmsgtool.h"
#include "kickfile.h"

/* Globals. */

static nmsgtool_ctx ctx;

#include "args.c"

/* Forward. */

static void io_closed(struct nmsg_io_close_event *);
static void setup_signals(void);
static void signal_handler(int);

/* Functions. */

int main(int argc, char **argv) {
	nmsg_res res;

	/* parse command line arguments */
	argv_process(args, argc, argv);
	if (ctx.debug >= 2)
		fprintf(stderr, "nmsgtool: version " VERSION "\n");

	/* load nmsgpb modules */
	ctx.ms = nmsg_pbmodset_init(NMSG_LIBDIR, ctx.debug);
	if (ctx.ms == NULL) {
		fprintf(stderr, "nmsgtool: unable to load modules "
			"(did you make install?)\n");
		return (nmsg_res_failure);
	}

	/* initialize the nmsg_io engine */
	ctx.io = nmsg_io_init();
	assert(ctx.io != NULL);
	nmsg_io_set_closed_fp(ctx.io, io_closed);
	setup_signals();

	/* process arguments and load inputs/outputs into the nmsg_io engine */
	process_args(&ctx);

	/* run the nmsg_io engine */
	res = nmsg_io_loop(ctx.io);

	/* cleanup */
	nmsg_io_destroy(&ctx.io);
	nmsg_pbmodset_destroy(&ctx.ms);
	free(ctx.endline);
	argv_cleanup(args);

	return (res);
}

void
usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

void
setup_nmsg_output(nmsgtool_ctx *c, nmsg_output_t output) {
	nmsg_output_set_buffered(output, !(c->unbuffered));
	nmsg_output_set_endline(output, c->endline);
	nmsg_output_set_zlibout(output, c->zlibout);
	nmsg_output_set_source(output, c->set_source);
	nmsg_output_set_operator(output, c->set_operator);
	nmsg_output_set_group(output, c->set_group);
}

/* Private functions. */

static void
io_closed(struct nmsg_io_close_event *ce) {
	struct kickfile *kf;

	if (ce->user != NULL && ce->io_type == nmsg_io_io_type_output &&
	    ce->output_type == nmsg_output_type_stream)
	{
		kf = (struct kickfile *) ce->user;
		kickfile_exec(kf);
		if (ce->close_type == nmsg_io_close_type_eof) {
			fprintf(stderr, "%s: closing output: %s\n",
				argv_program, kf->basename);
			kickfile_destroy(&kf);
		} else {
			kickfile_rotate(kf);
			*(ce->output) = nmsg_output_open_file(
				open_wfile(kf->tmpname), NMSG_WBUFSZ_MAX);
			setup_nmsg_output(&ctx, *(ce->output));
			if (ctx.debug >= 2)
				fprintf(stderr,
					"%s: reopening nmsg file output: %s\n",
					argv_program, kf->curname);
		}
	}

	if (ce->user != NULL && ce->io_type == nmsg_io_io_type_output &&
	    ce->output_type == nmsg_output_type_pres)
	{
		kf = (struct kickfile *) ce->user;
		kickfile_exec(kf);
		if (ce->close_type == nmsg_io_close_type_eof) {
			fprintf(stderr, "%s: closing output: %s\n",
				argv_program, kf->basename);
			kickfile_destroy(&kf);
		} else {
			kickfile_rotate(kf);
			*(ce->output) = nmsg_output_open_pres(
				open_wfile(kf->tmpname), ctx.ms);
			setup_nmsg_output(&ctx, *(ce->output));
			if (ctx.debug >= 2)
				fprintf(stderr,
					"%s: reopening pres file output: %s\n",
					argv_program, kf->curname);
		}
	}
}

static void
signal_handler(int sig __attribute__((unused))) {
	fprintf(stderr, "%s: signalled break\n", argv_program);
	nmsg_io_breakloop(ctx.io);
}

static void
setup_signals(void) {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGTERM);
	sa.sa_handler = &signal_handler;
	assert(sigaction(SIGINT, &sa, NULL) == 0);
	assert(sigaction(SIGTERM, &sa, NULL) == 0);
}
