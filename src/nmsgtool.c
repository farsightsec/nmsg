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
#include "chalias.h"
#include "kickfile.h"

/* Globals. */

static nmsgtool_ctx ctx;

#include "args.c"

/* Forward. */

static void io_closed(struct nmsg_io_close_event *);
static void process_args(nmsgtool_ctx *);
static void setup_signals(void);
static void signal_handler(int);

/* Functions. */

int main(int argc, char **argv) {
	nmsg_res res;

	argv_process(args, argc, argv);
	ctx.args = args;
	if (ctx.debug >= 2)
		fprintf(stderr, "nmsgtool: version " VERSION "\n");
	ctx.ms = nmsg_pbmodset_init(NMSG_LIBDIR, ctx.debug);
	if (ctx.ms == NULL) {
		fprintf(stderr, "nmsgtool: unable to load modules "
			"(did you make install?)\n");
		return (nmsg_res_failure);
	}
	ctx.io = nmsg_io_init();
	assert(ctx.io != NULL);
	process_args(&ctx);
	nmsg_io_set_closed_fp(ctx.io, io_closed);
	if (ctx.mirror == true)
		nmsg_io_set_output_mode(ctx.io, nmsg_io_output_mode_mirror);
	setup_signals();
	res = nmsg_io_loop(ctx.io);
	nmsg_io_destroy(&ctx.io);
	nmsg_pbmodset_destroy(&ctx.ms);
	free(ctx.endline);
	ctx.endline = NULL;
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

static void
process_args(nmsgtool_ctx *c) {
	nmsg_pbmod_t mod = NULL;

	if (c->help)
		usage(NULL);
	if (c->endline == NULL) {
		c->endline = strdup("\n");
	} else {
		char *tmp = c->endline;
		c->endline = unescape(c->endline);
		free(tmp);
	}
	if (c->mtu == 0)
		c->mtu = NMSG_WBUFSZ_JUMBO;
	if (c->vname != NULL) {
		if (c->mname == NULL)
			usage("-V requires -T");
		c->vendor = nmsg_pbmodset_vname_to_vid(c->ms, c->vname);
		if (c->vendor == 0)
			usage("invalid vendor ID");
		if (c->debug >= 2)
			fprintf(stderr, "%s: pres input vendor = %s\n",
				argv_program, c->vname);
	}
	if (c->mname != NULL) {
		if (c->vname == NULL)
			usage("-T requires -V");
		c->msgtype = nmsg_pbmodset_mname_to_msgtype(c->ms, c->vendor,
							    c->mname);
		if (c->msgtype == 0)
			usage("invalid message type");
		if (c->debug >= 2)
			fprintf(stderr, "%s: pres input msgtype = %s\n",
				argv_program, c->mname);
	}
	if (c->debug > 0)
		nmsg_io_set_debug(c->io, c->debug);
	if (c->count > 0)
		nmsg_io_set_count(c->io, c->count);
	if (c->interval > 0)
		nmsg_io_set_interval(c->io, c->interval);

	if (c->set_source_str != NULL) {
		char *t;

		c->set_source = (unsigned) strtoul(c->set_source_str, &t, 0);
		if (*t != '\0')
			usage("invalid source ID");
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg source set to %#.08x\n",
				argv_program, c->set_source);
	}

	if (c->set_operator_str != NULL) {
		c->set_operator = nmsg_alias_by_value(nmsg_alias_operator,
						      c->set_operator_str);
		if (c->set_operator == 0)
			usage("unknown operator name");
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg operator set to '%s' (%u)\n",
				argv_program,
				c->set_operator_str,
				c->set_operator);
	}

	if (c->set_group_str != NULL) {
		c->set_group = nmsg_alias_by_value(nmsg_alias_group,
						   c->set_group_str);
		if (c->set_group == 0)
			usage("unknown group name");
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg group set to '%s' (%u)\n",
				argv_program,
				c->set_group_str,
				c->set_group);
	}

	if (ARGV_ARRAY_COUNT(c->r_pres) > 0 ||
	    ARGV_ARRAY_COUNT(c->r_pcapfile) > 0 ||
	    ARGV_ARRAY_COUNT(c->r_pcapif) > 0)
	{
		if (c->vname == NULL || c->mname == NULL)
			usage("reading presentation or pcap data requires "
			      "-V, -T");
		mod = nmsg_pbmodset_lookup(c->ms, c->vendor, c->msgtype);
		if (mod == NULL)
			usage("unknown pbmod");
	}

#define process_args_loop(arry, func) do { \
	for (int i = 0; i < ARGV_ARRAY_COUNT(arry); i++) \
		func(c, *ARGV_ARRAY_ENTRY_P(arry, char *, i)); \
} while(0)

#define process_args_loop_mod(arry, func, mod) do { \
	for (int i = 0; i < ARGV_ARRAY_COUNT(arry); i++) \
		func(c, mod, *ARGV_ARRAY_ENTRY_P(arry, char *, i)); \
} while(0)

	/* nmsg inputs and outputs */
	process_args_loop(c->r_sock, add_sock_input);
	process_args_loop(c->w_sock, add_sock_output);
	process_args_loop(c->r_nmsg, add_file_input);
	process_args_loop(c->w_nmsg, add_file_output);

	for (int i = 0; i < ARGV_ARRAY_COUNT(c->r_channel); i++) {
		char *ch;
		char **alias = NULL;
		int j;
		int num_aliases;

		ch = *ARGV_ARRAY_ENTRY_P(c->r_channel, char *, i);
		if (c->debug >= 2)
			fprintf(stderr, "%s: looking up channel '%s' in %s\n",
				argv_program, ch, CHALIAS_FILE);
		num_aliases = chalias_lookup(CHALIAS_FILE, ch, &alias);
		if (num_aliases < 0) {
			perror("chalias_lookup");
			usage("channel alias lookup failed");
		}
		for (j = 0; j < num_aliases; j++)
			add_sock_input(&ctx, alias[j]);
		chalias_free(alias);
	}

	/* pres inputs and outputs */
	process_args_loop_mod(c->r_pres, add_pres_input, mod);
	process_args_loop(c->w_pres, add_pres_output);

	/* pcap inputs */
	process_args_loop_mod(c->r_pcapfile, add_pcapfile_input, mod);
	process_args_loop_mod(c->r_pcapif, add_pcapif_input, mod);

	/* validation */
	if (c->n_inputs == 0)
		usage("no data sources specified");
	if (c->n_outputs == 0)
		usage("no data sinks specified");
}
