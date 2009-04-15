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
#include <pcap.h>

#include "argv.h"
#include "chalias.h"
#include "kickfile.h"

/* Data structures. */

union nmsgtool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};
typedef union nmsgtool_sockaddr nmsgtool_sockaddr;

typedef struct {
	/* parameters */
	argv_array_t	r_nmsg, r_pres, r_sock, r_channel;
	argv_array_t	r_pcapfile, r_pcapif;
	argv_array_t	w_nmsg, w_pres, w_sock;
	bool		help, mirror, flush, unbuffered, zlibout;
	char		*endline, *kicker, *mname, *vname, *bpfstr;
	int		debug;
	unsigned	mtu, count, interval, rate, freq;
	unsigned	user0, user1;

	/* state */
	argv_t		*args;
	int		n_inputs, n_outputs;
	nmsg_io_t	io;
	nmsg_pbmodset_t	ms;
	uint64_t	count_total;
	unsigned	msgtype, vendor;
} nmsgtool_ctx;

/* Globals. */

static nmsgtool_ctx ctx;
static const int on = 1;

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

	{ 'F', "flush",
		ARGV_BOOL,
		&ctx.flush,
		NULL,
		"flush outputs after every bufferable write" },

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

	{ '0',	"user0",
		ARGV_HEX,
		&ctx.user0,
		"val",
		"set user0 to this hex value" },

	{ '1',	"user1",
		ARGV_HEX,
		&ctx.user1,
		"val",
		"set user1 to this hex value" },

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
		"read nmsg data from socket (addr/port)" },

	{ 'C', "readchan",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.r_channel,
		"channel",
		"read nmsg data from socket(s)" },

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

	{ 's', "writesock",
		ARGV_CHAR_P | ARGV_FLAG_ARRAY,
		&ctx.w_sock,
		"so[,r[,f]]",
		"write nmsg data to socket (addr/port)" },

	{ 'z', "zlibout",
		ARGV_BOOL,
		&ctx.zlibout,
		NULL,
		"compress nmsg output" },

	{ '\0', "mirror",
		ARGV_BOOL,
		&ctx.mirror,
		NULL,
		"mirror payloads across data outputs" },

	{ '\0', "unbuffered",
		ARGV_BOOL,
		&ctx.unbuffered,
		NULL,
		"don't buffer payloads on nmsg socket outputs" },

	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

/* Macros. */

#define Setsockopt(s, lvl, name, val) do { \
	if (setsockopt(s, lvl, name, &val, sizeof(val)) < 0) { \
		perror("setsockopt(" #name ")"); \
		exit(1); \
	} \
} while(0)

#ifdef HAVE_SA_LEN
#define NMSGTOOL_SA_LEN(sa) ((sa).sa_len)
#else
#define NMSGTOOL_SA_LEN(sa) ((sa).sa_family == AF_INET ? \
			     sizeof(struct sockaddr_in) : \
			     (sa).sa_family == AF_INET6 ? \
			     sizeof(struct sockaddr_in6) : 0)
#endif

#define DEFAULT_FREQ	100
#define CHALIAS_FILE	NMSG_ETCDIR "/nmsgtool.chalias"

/* Forward. */

static int getsock(nmsgtool_sockaddr *, const char *addr, unsigned *rate,
		   unsigned *freq);
static int open_rfile(const char *);
static int open_wfile(const char *);
static void add_file_input(nmsgtool_ctx *, const char *);
static void add_file_output(nmsgtool_ctx *, const char *);
static void add_pcapfile_input(nmsgtool_ctx *, nmsg_pbmod_t mod, const char *);
static void add_pcapif_input(nmsgtool_ctx *, nmsg_pbmod_t mod, const char *);
static void add_pres_input(nmsgtool_ctx *, nmsg_pbmod_t, const char *);
static void add_pres_output(nmsgtool_ctx *, const char *);
static void add_sock_input(nmsgtool_ctx *, const char *);
static void add_sock_output(nmsgtool_ctx *, const char *);
static void io_closed(struct nmsg_io_close_event *);
static void process_args(nmsgtool_ctx *);
static void setup_nmsg_output(nmsgtool_ctx *, nmsg_output_t);
static void setup_signals(void);
static void signal_handler(int);
static void usage(const char *);

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

/* Private functions. */

static void
usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

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
	if (c->endline == NULL)
		c->endline = strdup("\n");
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

static void
add_sock_input(nmsgtool_ctx *c, const char *ss) {
	char *t;
	int pa, pz, pn, pl;

	t = strchr(ss, '/');
	if (t == NULL)
		usage("argument to -l needs a /");
	if (sscanf(t + 1, "%d..%d", &pa, &pz) == 2) {
		if (pa > pz || pz - pa > 20)
			usage("bad port range in -l argument");
	} else if (sscanf(t + 1, "%d", &pa) == 1) {
		pz = pa;
	} else {
		usage("need a port number or range after /");
	}
	pl = t - ss;
	for (pn = pa; pn <= pz; pn++) {
		char *spec;
		int len, pf, s;
		nmsgtool_sockaddr su;
		nmsg_input_t input;
		nmsg_res res;

		nmsg_asprintf(&spec, "%*.*s/%d", pl, pl, ss, pn);
		pf = getsock(&su, spec, NULL, NULL);
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg socket input: %s\n",
				argv_program, spec);
		free(spec);
		if (pf < 0)
			usage("bad -l socket");
		s = socket(pf, SOCK_DGRAM, 0);
		if (s < 0) {
			perror("socket");
			exit(1);
		}
		Setsockopt(s, SOL_SOCKET, SO_REUSEADDR, on);
#ifdef SO_REUSEPORT
		Setsockopt(s, SOL_SOCKET, SO_REUSEPORT, on);
#endif
		len = 32 * 1024;
		Setsockopt(s, SOL_SOCKET, SO_RCVBUF, len);
		if (bind(s, &su.sa, NMSGTOOL_SA_LEN(su.sa)) < 0) {
			perror("bind");
			exit(1);
		}
		input = nmsg_input_open_sock(s);
		res = nmsg_io_add_input(c->io, input, NULL);
		if (res != nmsg_res_success) {
			fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
				argv_program);
			exit(1);
		}
		c->n_inputs += 1;
	}
}

static void
add_sock_output(nmsgtool_ctx *c, const char *ss) {
	char *r, *t;
	int pa, pz, pn, pl;

	t = strchr(ss, '/');
	r = strchr(ss, ',');
	if (t == NULL)
		usage("argument to -s needs a /");
	if (sscanf(t + 1, "%d..%d", &pa, &pz) == 2) {
		if (pa > pz || pz - pa > 20)
			usage("bad port range in -s argument");
	} else if (sscanf(t + 1, "%d", &pa) == 1) {
		pz = pa;
	} else {
		usage("need a port number or range after /");
	}
	pl = t - ss;
	for (pn = pa; pn <= pz; pn++) {
		char *spec;
		int len, pf, s;
		nmsgtool_sockaddr su;
		nmsg_output_t output;
		nmsg_res res;
		unsigned rate = 0, freq = 0;

		nmsg_asprintf(&spec, "%*.*s/%d%s", pl, pl, ss, pn,
			      r != NULL ? r : "");
		pf = getsock(&su, spec, &rate, &freq);
		if (freq == 0)
			freq = DEFAULT_FREQ;
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg socket output: %s\n",
				argv_program, spec);
		if (c->debug >= 2 && rate > 0)
			fprintf(stderr, "%s: nmsg socket rate: %u freq: %u\n",
				argv_program, rate, freq);
		free(spec);
		if (pf < 0)
			usage("bad -s socket");
		s = socket(pf, SOCK_DGRAM, 0);
		if (s < 0) {
			perror("socket");
			exit(1);
		}
		Setsockopt(s, SOL_SOCKET, SO_BROADCAST, on);
		len = 32 * 1024;
		Setsockopt(s, SOL_SOCKET, SO_SNDBUF, len);
		if (connect(s, &su.sa, NMSGTOOL_SA_LEN(su.sa)) < 0) {
			perror("connect");
			exit(1);
		}
		output = nmsg_output_open_sock(s, c->mtu);
		setup_nmsg_output(c, output);
		if (rate > 0 && freq > 0) {
			nmsg_rate_t nr;

			nr = nmsg_rate_init(rate, freq);
			assert(nr != NULL);
			nmsg_output_set_rate(output, nr);
		}
		res = nmsg_io_add_output(c->io, output, NULL);
		if (res != nmsg_res_success) {
			fprintf(stderr, "%s: nmsg_io_add_output() failed\n",
				argv_program);
			exit(1);
		}
		c->n_outputs += 1;
	}
}

static void
add_file_input(nmsgtool_ctx *c, const char *fname) {
	nmsg_input_t input;
	nmsg_res res;

	input = nmsg_input_open_file(open_rfile(fname));
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg file input: %s\n", argv_program,
			fname);
	c->n_inputs += 1;
}

static void
add_file_output(nmsgtool_ctx *c, const char *fname) {
	nmsg_output_t output;
	nmsg_res res;

	if (c->kicker != NULL) {
		struct kickfile *kf;

		kf = calloc(1, sizeof(*kf));
		assert(kf != NULL);

		kf->cmd = c->kicker;
		kf->basename = strdup(fname);
		kf->suffix = strdup(".nmsg");
		kickfile_rotate(kf);

		output = nmsg_output_open_file(open_wfile(kf->tmpname),
					       NMSG_WBUFSZ_MAX);
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, (void *) kf);
	} else {
		output = nmsg_output_open_file(open_wfile(fname),
					       NMSG_WBUFSZ_MAX);
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, NULL);
	}
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_output() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg file output: %s\n", argv_program,
			fname);
	c->n_outputs += 1;
}

static void
add_pcapfile_input(nmsgtool_ctx *c, nmsg_pbmod_t mod, const char *fname) {
	char errbuf[PCAP_ERRBUF_SIZE];
	nmsg_input_t input;
	nmsg_pcap_t pcap;
	nmsg_res res;
	pcap_t *phandle;

	phandle = pcap_open_offline(fname, errbuf);
	if (phandle == NULL) {
		fprintf(stderr, "%s: unable to add pcap file input %s: %s\n",
			argv_program, fname, errbuf);
		exit(1);
	}

	pcap = nmsg_pcap_input_open(phandle);
	if (pcap == NULL) {
		fprintf(stderr, "%s: nmsg_pcap_input_open() failed\n",
			argv_program);
		exit(1);
	}
	input = nmsg_input_open_pcap(pcap, mod);
	if (input == NULL) {
		fprintf(stderr, "%s: nmsg_input_open_pcap() failed\n",
			argv_program);
	}
	if (c->bpfstr != NULL) {
		res = nmsg_pcap_input_setfilter(pcap, c->bpfstr);
		if (res != nmsg_res_success)
			exit(1);
	}
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: pcap file input: %s\n", argv_program,
			fname);
	c->n_inputs += 1;
}

static void
add_pcapif_input(nmsgtool_ctx *c, nmsg_pbmod_t mod, const char *arg) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char *iface, *ssnaplen, *spromisc;
	char *saveptr = NULL;
	char *tmp;
	int snaplen = NMSG_DEFAULT_SNAPLEN;
	int promisc = 0;
	nmsg_input_t input;
	nmsg_pcap_t pcap;
	nmsg_res res;
	pcap_t *phandle;

	tmp = strdup(arg);
	iface = strtok_r(tmp, ",", &saveptr);
	ssnaplen = strtok_r(NULL, ",", &saveptr);
	spromisc = strchr(iface, '+');

	if (ssnaplen != NULL) {
		char *t;
		snaplen = (int) strtol(ssnaplen, &t, 0);
		if (*t != '\0' || snaplen < 0) {
			fprintf(stderr, "%s: parse error: "
				"'%s' is not a valid snaplen\n",
				argv_program, ssnaplen);
			exit(1);
		}
	}
	if (spromisc != NULL) {
		promisc = 1;
		*spromisc = '\0';
	}

	phandle = pcap_open_live(iface, snaplen, promisc, 0, errbuf);
	if (phandle == NULL) {
		fprintf(stderr, "%s: unable to add pcap interface input "
			"%s: %s\n", argv_program, iface, errbuf);
		exit(1);
	}

	pcap = nmsg_pcap_input_open(phandle);
	if (pcap == NULL) {
		fprintf(stderr, "%s: nmsg_pcap_input_open() failed\n",
			argv_program);
		exit(1);
	}
	input = nmsg_input_open_pcap(pcap, mod);
	if (input == NULL) {
		fprintf(stderr, "%s: nmsg_input_open_pcap() failed\n",
			argv_program);
	}
	if (c->bpfstr != NULL) {
		res = nmsg_pcap_input_setfilter(pcap, c->bpfstr);
		if (res != nmsg_res_success)
			exit(1);
	}
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
			argv_program);
		exit(1);
	}

	if (c->debug >= 2)
		fprintf(stderr, "%s: pcap interface input: %s\n",
			argv_program, arg);

	c->n_inputs += 1;
	free(tmp);
}

static void
add_pres_input(nmsgtool_ctx *c, nmsg_pbmod_t mod, const char *fname) {
	nmsg_input_t input;
	nmsg_res res;

	input = nmsg_input_open_pres(open_rfile(fname), mod);
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg pres input: %s\n", argv_program,
			fname);
	c->n_inputs += 1;
}

static void
add_pres_output(nmsgtool_ctx *c, const char *fname) {
	nmsg_output_t output;
	nmsg_res res;

	if (c->kicker != NULL) {
		struct kickfile *kf;
		kf = calloc(1, sizeof(*kf));
		assert(kf != NULL);

		kf->cmd = c->kicker;
		kf->basename = strdup(fname);
		kickfile_rotate(kf);

		output = nmsg_output_open_pres(open_wfile(kf->tmpname),
					       ctx.ms);
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, (void *) kf);
	} else {
		output = nmsg_output_open_pres(open_wfile(fname), ctx.ms);
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, NULL);
	}
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_output() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg pres output: %s\n", argv_program,
			fname);
	c->n_outputs += 1;
}

static int
getsock(nmsgtool_sockaddr *su, const char *addr, unsigned *rate,
	unsigned *freq)
{
	char *tmp = strdup(addr);
	char *p = strchr(tmp, '/');
	unsigned port, pf;
	char *t;

	memset(su, 0, sizeof(*su));
	if (p == NULL) {
		fprintf(stderr, "getsock: no slash found\n");
		free(tmp);
		return (-1);
	}
	*p++ = '\0';
	port = strtoul(p, &t, 0);
	if (*t == ',' && rate != NULL && freq != NULL) {
		u_long t_rate, t_freq;

		t_rate = strtoul(t+1, &t, 0);
		if (*t == ',') {
			t_freq = strtoul(t+1, &t, 0);
			if (*t != '\0') {
				fprintf(stderr, "getsock: bad frequency (%s)\n",
					addr);
				free(tmp);
				return (-1);
			}
			*freq = t_freq;
		} else if (*t != '\0') {
			fprintf(stderr, "getsock: invalid packet rate (%s)\n",
				addr);
			free(tmp);
			return (-1);
		}
		*rate = t_rate;
	}
	if (*t != '\0' || port == 0) {
		fprintf(stderr, "getsock: invalid port number\n");
		free(tmp);
		return (-1);
	}
	if (inet_pton(AF_INET6, tmp, &su->s6.sin6_addr)) {
#ifdef HAVE_SA_LEN
		su->s6.sin6_len = sizeof(su->s6);
#endif
		su->s6.sin6_family = AF_INET6;
		su->s6.sin6_port = htons(port);
		pf = PF_INET6;
	} else if (inet_pton(AF_INET, tmp, &su->s4.sin_addr)) {
#ifdef HAVE_SA_LEN
		su->s4.sin_len = sizeof(su->s4);
#endif
		su->s4.sin_family = AF_INET;
		su->s4.sin_port = htons(port);
		pf = PF_INET;
	} else {
		fprintf(stderr, "getsock: addr is not valid inet or inet6\n");
		free(tmp);
		return (-1);
	}
	free(tmp);
	return (pf);
}

static void
setup_nmsg_output(nmsgtool_ctx *c, nmsg_output_t output) {
	nmsg_output_set_buffered(output, !(c->unbuffered));
	nmsg_output_set_endline(output, c->endline);
	nmsg_output_set_zlibout(output, c->zlibout);
	if (argv_was_used(c->args, '0'))
		nmsg_output_set_user(output, 0, c->user0);
	if (argv_was_used(c->args, '1'))
		nmsg_output_set_user(output, 1, c->user1);
}

static int
open_rfile(const char *fname) {
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
	return (fd);
}

static int
open_wfile(const char *fname) {
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
	return (fd);
}
