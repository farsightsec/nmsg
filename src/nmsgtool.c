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

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nmsg.h>

#include "nmsgtool.h"
#include "kickfile.h"

/* Globals. */

static nmsgtool_ctx ctx;

#include "args.c"

/* Forward. */

static void io_close(struct nmsg_io_close_event *);
static void setup_signals(void);
static void signal_handler(int);

/* Functions. */

int main(int argc, char **argv) {
	nmsg_res res;

	/* parse command line arguments */
	argv_process(args, argc, argv);

	nmsg_set_debug(ctx.debug);
	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "nmsgtool: unable to initialize libnmsg\n");
		return (EXIT_FAILURE);
	}
	if (ctx.debug >= 2)
		fprintf(stderr, "nmsgtool: version " VERSION "\n");

	/* initialize the nmsg_io engine */
	ctx.io = nmsg_io_init();
	assert(ctx.io != NULL);
	nmsg_io_set_close_fp(ctx.io, io_close);

	/* process arguments and load inputs/outputs into the nmsg_io engine */
	process_args(&ctx);

	setup_signals();

	/* run the nmsg_io engine */
	res = nmsg_io_loop(ctx.io);

	/* cleanup */
	if (ctx.pidfile != NULL) {
		if (unlink(ctx.pidfile) != 0) {
			fprintf(stderr, "nmsgtool: unlink() failed: %s\n",
				strerror(errno));
		}
	}
	nmsg_io_destroy(&ctx.io);
	if (ctx.zmq_ctx)
		zmq_term(ctx.zmq_ctx);
	free(ctx.endline_str);
	argv_cleanup(args);

	return (res);
}

void
usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	nmsg_io_destroy(&ctx.io);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

void
setup_nmsg_output(nmsgtool_ctx *c, nmsg_output_t output) {
	nmsg_output_set_buffered(output, !(c->unbuffered));
	nmsg_output_set_endline(output, c->endline_str);
	nmsg_output_set_zlibout(output, c->zlibout);
	nmsg_output_set_source(output, c->set_source);
	nmsg_output_set_operator(output, c->set_operator);
	nmsg_output_set_group(output, c->set_group);
}

void
setup_nmsg_input(nmsgtool_ctx *c, nmsg_input_t input) {
	if (c->vid != 0 && c->msgtype != 0)
		nmsg_input_set_filter_msgtype(input, c->vid, c->msgtype);
	nmsg_input_set_filter_source(input, c->get_source);
	nmsg_input_set_filter_operator(input, c->get_operator);
	nmsg_input_set_filter_group(input, c->get_group);
}

/* Private functions. */

static void
io_close(struct nmsg_io_close_event *ce) {
	struct kickfile *kf;

	if (ctx.debug >= 5) {
		fprintf(stderr, "entering io_close()\n");
		fprintf(stderr, "%s: ce->io_type = %u\n", __func__, ce->io_type);
		fprintf(stderr, "%s: ce->close_type = %u\n", __func__, ce->close_type);
		fprintf(stderr, "%s: ce->user = %p\n", __func__, ce->user);
		if (ce->io_type == nmsg_io_io_type_input) {
			fprintf(stderr, "%s: ce->input_type = %u\n", __func__, ce->input_type);
			fprintf(stderr, "%s: ce->input = %p\n", __func__, ce->input);
		} else if (ce->io_type == nmsg_io_io_type_output) {
			fprintf(stderr, "%s: ce->output_type = %u\n", __func__, ce->output_type);
			fprintf(stderr, "%s: ce->output = %p\n", __func__, ce->output);
		}
	}

	if (ce->user != NULL && ce->user != (void *) -1 &&
	    ce->io_type == nmsg_io_io_type_output &&
	    ce->output_type == nmsg_output_type_stream)
	{
		nmsg_output_close(ce->output);

		kf = (struct kickfile *) ce->user;
		kickfile_exec(kf);
		if (ce->close_type == nmsg_io_close_type_eof) {
			if (ctx.debug >= 2)
				fprintf(stderr, "%s: closed output: %s\n",
					argv_program, kf->basename);
			kickfile_destroy(&kf);
		} else {
			kickfile_rotate(kf);
			*(ce->output) = nmsg_output_open_file(
				open_wfile(kf->tmpname), NMSG_WBUFSZ_MAX);
			setup_nmsg_output(&ctx, *(ce->output));
			if (ctx.debug >= 2)
				fprintf(stderr,
					"%s: reopened nmsg file output: %s\n",
					argv_program, kf->curname);
		}
	} else if (ce->user != NULL && ce->user != (void *) -1 &&
		   ce->io_type == nmsg_io_io_type_output &&
		   ce->output_type == nmsg_output_type_pres)
	{
		nmsg_output_close(ce->output);

		kf = (struct kickfile *) ce->user;
		kickfile_exec(kf);
		if (ce->close_type == nmsg_io_close_type_eof) {
			if (ctx.debug >= 2)
				fprintf(stderr, "%s: closed output: %s\n",
					argv_program, kf->basename);
			kickfile_destroy(&kf);
		} else {
			kickfile_rotate(kf);
			*(ce->output) = nmsg_output_open_pres(
				open_wfile(kf->tmpname));
			setup_nmsg_output(&ctx, *(ce->output));
			if (ctx.debug >= 2)
				fprintf(stderr,
					"%s: reopened pres file output: %s\n",
					argv_program, kf->curname);
		}
	} else if (ce->io_type == nmsg_io_io_type_input) {
		if ((ce->user == NULL || ce->close_type == nmsg_io_close_type_eof) &&
		     ce->input != NULL)
		{
			if (ctx.debug >= 5) {
				fprintf(stderr, "%s: closing input %p\n", __func__, ce->input);
			}
			nmsg_input_close(ce->input);
		}
	} else if (ce->io_type == nmsg_io_io_type_output) {
		if ((ce->user == NULL || ce->close_type == nmsg_io_close_type_eof) &&
		     ce->output != NULL)
		{
			if (ctx.debug >= 5) {
				fprintf(stderr, "%s: closing output %p\n", __func__, ce->output);
			}
			nmsg_output_close(ce->output);
		}
	} else {
		/* should never be reached */
		assert(0);
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
	if (sigaction(SIGINT, &sa, NULL) != 0) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &sa, NULL) != 0) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}
}
