/*
 * Copyright (c) 2008-2019 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

	{ 'B', "byterate",
		ARGV_INT,
		&ctx.byte_rate,
		"byterate",
		"ingress byte rate limit for file input" },

	{ 'e', "endline",
		ARGV_CHAR_P,
		&ctx.endline,
		"endline",
		"continuation separator" },

	{ 'm', "mtu",
		ARGV_INT,
		&ctx.mtu,
		"mtu",
		"MTU for datagram socket outputs" },

	{ 'c',	"count",
		ARGV_INT,
		&ctx.count,
		"count",
		"stop or reopen after count payloads output" },

	{ 't',	"interval",
		ARGV_INT,
		&ctx.interval,
		"secs",
		"stop or reopen after secs have elapsed" },

	{ 'R', "randomize",
		ARGV_BOOL,
		&ctx.interval_randomized,
		NULL,
		"randomize beginning of -t interval" },

	{ 'k',	"kicker",
		ARGV_CHAR_P,
		&ctx.kicker,
		"cmd",
		"make -c, -t continuous; run cmd on new files" },

	{ 'b',	"bpf",
		ARGV_CHAR_P,
		&ctx.bpfstr,
		"filter",
		"filter pcap inputs with this bpf" },

	{ 'F',	"filter",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.filters,
		"dso[,param]",
		"filter nmsg payloads with module" },

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

	{ 'j', "readjson",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_json,
		"file",
#ifdef HAVE_YAJL
		"read json format data from file" },
#else /* HAVE_YAJL */
		"read json format data from file (no support)" },
#endif /* HAVE_YAJL */

	{ 'l', "readsock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_sock,
		"so",
		"read nmsg data from socket (addr/port)" },

	{ 'L', "readxsock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_xsock,
		"xep",
#ifdef HAVE_LIBXS
		"read nmsg data from XS endpoint" },
#else /* HAVE_LIBXS */
		"read nmsg data from XS endpoint (no support)" },
#endif /* HAVE_LIBXS */

	{ 'C', "readchan",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_channel,
		"channel",
		"read nmsg data from socket(s)" },

	{ 'X', "readxchan",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_xchannel,
		"xchannel",
		"read nmsg data from XS channels" },

	{ 'p',	"readpcap",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_pcapfile,
		"file",
		"read pcap data from file" },

	{ 'i',	"readif",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_pcapif,
		"if[+][,snap]",
		"read pcap data from interface ('+' = promisc)" },

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

	{ 'J', "writejson",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_json,
		"file",
#ifdef HAVE_YAJL
		"write json format data to file" },
#else /* HAVE_YAJL */
		"write json format data to file (no support)" },
#endif /* HAVE_YAJL */

	{ 's', "writesock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_sock,
		"so[,r[,f]]",
		"write nmsg data to socket (addr/port)" },

	{ 'S', "writexsock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_xsock,
		"xep",
#ifdef HAVE_LIBXS
		"write nmsg data to XS endpoint" },
#else /* HAVE_LIBXS */
		"write nmsg data to XS endpoint (no support)" },
#endif /* HAVE_LIBXS */

	{ 'z', "zlibout",
		ARGV_BOOL,
		&ctx.zlibout,
		NULL,
		"compress nmsg output" },

	{ 'D', "daemon",
		ARGV_BOOL,
		&ctx.daemon,
		NULL,
		"fork into background" },

	{ 'P', "pidfile",
		ARGV_CHAR_P,
		&ctx.pidfile,
		"file",
		"write PID into file" },

	{ 'U', "username",
		ARGV_CHAR_P,
		&ctx.username,
		"user",
		"drop privileges and run as user" },

	{ 'v', "version",
		ARGV_BOOL,
		&ctx.version,
		NULL,
		"print version" },

	{ '\0', "mirror",
		ARGV_BOOL,
		&ctx.mirror,
		NULL,
		"mirror payloads across data outputs" },

	{ '\0', "unbuffered",
		ARGV_BOOL,
		&ctx.unbuffered,
		NULL,
		"don't buffer writes to outputs" },

	{ '\0', "policy",
		ARGV_CHAR_P,
		&ctx.filter_policy,
		"ACCEPT|DROP",
		"default filter chain policy" },

	{ '\0',	"setsource",
		ARGV_CHAR_P,
		&ctx.set_source_str,
		"sonum",
		"set payload source to this value" },

	{ '\0', "getsource",
		ARGV_CHAR_P,
		&ctx.get_source_str,
		"sonum",
		"only process payloads with this source value" },

	{ '\0',	"setoperator",
		ARGV_CHAR_P,
		&ctx.set_operator_str,
		"opname",
		"set payload operator to this value" },

	{ '\0', "getoperator",
		ARGV_CHAR_P,
		&ctx.get_operator_str,
		"opname",
		"only process payloads with this operator name" },

	{ '\0',	"setgroup",
		ARGV_CHAR_P,
		&ctx.set_group_str,
		"grname",
		"set payload group to this value" },

	{ '\0',	"getgroup",
		ARGV_CHAR_P,
		&ctx.get_group_str,
		"grname",
		"only process payloads with this group name" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

/* Forward. */

static void io_close(struct nmsg_io_close_event *);
static void setup_signals(void);
static void signal_handler(int);

/* Functions. */

int main(int argc, char **argv) {
	nmsg_res res;

	/* parse command line arguments */
	argv_process(args, argc, argv);

	if (ctx.debug < 1)
		ctx.debug = 1;
	nmsg_set_debug(ctx.debug);
	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "nmsgtool: unable to initialize libnmsg\n");
		return (EXIT_FAILURE);
	}
	if (ctx.debug >= 2)
#ifdef HAVE_LIBXS
		fprintf(stderr, "nmsgtool: version " VERSION "\n");
#else /* HAVE_LIBXS */
		fprintf(stderr, "nmsgtool: version " VERSION " (without libxs support)\n");
#endif /* HAVE_LIBXS */

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
#ifdef HAVE_LIBXS
	if (ctx.xs_ctx)
		xs_term(ctx.xs_ctx);
#endif /* HAVE_LIBXS */
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

	if (ctx.debug >= 2) {
		if ((ctx.stats_output != NULL && *(ce->output) == ctx.stats_output) ||
			(ctx.stats_user != NULL && ce->user == ctx.stats_user)) {
			uint64_t sum_in = 0, sum_out = 0, container_drops = 0, container_recvs = 0;
			if (nmsg_io_get_stats(ce->io, &sum_in, &sum_out, &container_recvs, &container_drops) == nmsg_res_success)
				fprintf(stderr,
					"%s: totals: payloads_in %"PRIu64
					" payloads_out %"PRIu64
					" container_recvs %"PRIu64
				        " container_drops %"PRIu64"\n",
					argv_program, sum_in, sum_out, container_recvs, container_drops);
		}
	}

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
	    (ce->output_type == nmsg_output_type_stream ||
	     ce->output_type == nmsg_output_type_pres ||
	     ce->output_type == nmsg_output_type_json))
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

			char *output_type_descr = NULL;
			switch (ce->output_type) {
			case nmsg_output_type_stream:
				*(ce->output) = nmsg_output_open_file(
					open_wfile(kf->tmpname), NMSG_WBUFSZ_MAX);
				output_type_descr = "nmsg";
				break;
			case nmsg_output_type_pres:
				*(ce->output) = nmsg_output_open_pres(
					open_wfile(kf->tmpname));
				output_type_descr = "pres";
				break;
			case nmsg_output_type_json:
				*(ce->output) = nmsg_output_open_json(
					open_wfile(kf->tmpname));
				output_type_descr = "json";
				break;
			default:
				assert(0);
			}
			setup_nmsg_output(&ctx, *(ce->output));
			if (ctx.debug >= 2)
				fprintf(stderr,
					"%s: reopened %s file output: %s\n",
					argv_program, output_type_descr, kf->curname);
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
