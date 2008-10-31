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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include <nmsg.h>
#include "config.h"
#include "argv.h"
#include "nmsg_port.h"

/* Data structures. */

union nmsgtool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};
typedef union nmsgtool_sockaddr nmsgtool_sockaddr;

typedef struct {
        /* parameters */
        argv_array_t    r_nmsg, r_pres, r_sock;
        argv_array_t    w_nmsg, w_pres, w_sock;
        bool            help;
        bool            mirror;
        char *          endline;
        char *          mname;
        char *          vname;
        int             debug;
        size_t          mtu;
        unsigned        rate, freq;

        /* state */
        int             n_inputs, n_outputs;
        nmsg_io         io;
        nmsg_pbmodset   ms;
        uint64_t        count_total;
        unsigned        msgtype, vendor;
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

	{ 'e', "endline",
		ARGV_CHAR_P,
		&ctx.endline,
		"endline",
		"continuation separator (def = \\\\\\n)" },

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

#define Setsockopt(s, lvl, name, val) do { \
	if (setsockopt(s, lvl, name, &val, sizeof(val)) < 0) { \
		perror("setsockopt(" #name ")"); \
		exit(1); \
	} \
} while(0)

#ifdef HAVE_SA_LEN
#define SA_LEN(sa) ((sa).sa_len)
#else
#define SA_LEN(sa) ((sa).sa_family == AF_INET ? \
		    sizeof(struct sockaddr_in) : \
		    (sa).sa_family == AF_INET6 ? \
	            sizeof(struct sockaddr_in6) : 0)
#endif

#define DEFAULT_FREQ	100

/* Forward. */

static int getsock(nmsgtool_sockaddr *, const char *addr, const char *rem,
		   unsigned *rate, unsigned *freq);
static int open_rfile(const char *);
static int open_wfile(const char *);
static void add_sock_input(nmsgtool_ctx *, const char *ss);
static void add_file_input(nmsgtool_ctx *, const char *fn);
static void add_pres_input(nmsgtool_ctx *, nmsg_pbmod, const char *fn);
static void add_sock_output(nmsgtool_ctx *, const char *ss);
static void add_file_output(nmsgtool_ctx *, const char *fn);
static void add_pres_output(nmsgtool_ctx *, nmsg_pbmod, const char *fn);
static void io_closed(nmsg_io, nmsg_io_fd_type, void *);
static void process_args(nmsgtool_ctx *);
static void usage(const char *);

/* Functions. */

int main(int argc, char **argv) {
	argv_process(args, argc, argv);
	ctx.ms = nmsg_pbmodset_open(NMSG_LIBDIR, ctx.debug);
	assert(ctx.ms != NULL);
	ctx.io = nmsg_io_init(ctx.ms);
	assert(ctx.io != NULL);
	process_args(&ctx);
	nmsg_io_set_closed_fp(ctx.io, io_closed);
	nmsg_io_set_debug(ctx.io, ctx.debug);
	nmsg_io_set_endline(ctx.io, ctx.endline);
	if (ctx.mirror == true)
		nmsg_io_set_output_mode(ctx.io, nmsg_io_output_mode_mirror);
	nmsg_io_loop(ctx.io);
	nmsg_io_destroy(&ctx.io);
	nmsg_pbmodset_destroy(&ctx.ms);
	free(ctx.endline);
	argv_cleanup(args);
	return (0);
}

/* Private functions. */

static void
usage(const char *msg) {
	if (msg)
		fprintf(stderr, "%s: usage error: %s\n", argv_program, msg);
	exit(argv_usage(args, ARGV_USAGE_DEFAULT));
}

static void
io_closed(nmsg_io io, nmsg_io_fd_type type, void *user) {
	fprintf(stderr, "nmsgtool: closed io=%p type=%d user=%p\n",
		io, type, user);
}

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

	/* nmsg socket inputs */
	if (ARGV_ARRAY_COUNT(c->r_sock) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->r_sock); i++)
			add_sock_input(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->r_sock, char *, i));
	/* nmsg socket outputs */
	if (ARGV_ARRAY_COUNT(c->w_sock) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_sock); i++)
			add_sock_output(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->w_sock, char *, i));
	/* nmsg file inputs */
	if (ARGV_ARRAY_COUNT(c->r_nmsg) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->r_nmsg); i++)
			add_file_input(&ctx,
				*ARGV_ARRAY_ENTRY_P(c->r_nmsg, char *, i));
	/* nmsg file outputs */
	if (ARGV_ARRAY_COUNT(c->w_nmsg) > 0)
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_nmsg); i++)
			add_file_output(&ctx,
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
			add_pres_input(&ctx, mod,
				*ARGV_ARRAY_ENTRY_P(c->r_pres, char *, i));
	}
	/* pres file output */
	if (ARGV_ARRAY_COUNT(c->w_pres) > 0) {
		nmsg_pbmod mod;
		mod = nmsg_pbmodset_lookup(c->ms, c->vendor, c->msgtype);
		for (i = 0; i < ARGV_ARRAY_COUNT(c->w_pres); i++)
			add_pres_output(&ctx, mod,
				*ARGV_ARRAY_ENTRY_P(c->w_pres, char *, i));
	}

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
		nmsg_buf buf;
		nmsg_res res;

		asprintf(&spec, "%*.*s/%d", pl, pl, ss, pn);
		pf = getsock(&su, spec, NULL, NULL, NULL);
		if (c->debug > 0)
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
		if (bind(s, &su.sa, SA_LEN(su.sa)) < 0) {
			perror("bind");
			exit(1);
		}
		buf = nmsg_input_open(s);
		res = nmsg_io_add_buf(c->io, buf, NULL);
		if (res != nmsg_res_success) {
			perror("nmsg_io_add_buf");
			exit(1);
		}
		c->n_inputs += 1;
	}
}

static void
add_sock_output(nmsgtool_ctx *c, const char *ss) {
	char *t, *rem;
	int pa, pz, pn, pl;

	t = strchr(ss, '/');
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
	rem = strchr(t, ',');
	for (pn = pa; pn <= pz; pn++) {
		char *spec;
		int len, pf, s;
		nmsgtool_sockaddr su;
		nmsg_buf buf;
		nmsg_res res;
		unsigned rate, freq;

		asprintf(&spec, "%*.*s/%d", pl, pl, ss, pn);
		if (c->debug > 0)
			fprintf(stderr, "%s: nmsg socket output: %s\n",
				argv_program, spec);
		pf = getsock(&su, spec, rem, &rate, &freq);
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
		if (connect(s, &su.sa, SA_LEN(su.sa)) < 0) {
			perror("connect");
			exit(1);
		}
		buf = nmsg_output_open_sock(s, c->mtu);
		nmsg_output_set_rate(buf, rate, freq);
		res = nmsg_io_add_buf(c->io, buf, NULL);
		if (res != nmsg_res_success) {
			perror("nmsg_io_add_buf");
			exit(1);
		}
		c->n_outputs += 1;
	}
}

static void
add_file_input(nmsgtool_ctx *c, const char *fname) {
	nmsg_buf buf;
	nmsg_res res;

	buf = nmsg_input_open(open_rfile(fname));
	res = nmsg_io_add_buf(c->io, buf, NULL);
	if (res != nmsg_res_success) {
		perror("nmsg_io_add_buf");
		exit(1);
	}
	if (c->debug >= 1)
		fprintf(stderr, "%s: nmsg file input: %s\n", argv_program,
			fname);
	c->n_inputs += 1;
}

static void
add_file_output(nmsgtool_ctx *c, const char *fname) {
	nmsg_buf buf;
	nmsg_res res;

	buf = nmsg_output_open_file(open_wfile(fname), nmsg_wbufsize_max);
	res = nmsg_io_add_buf(c->io, buf, NULL);
	if (res != nmsg_res_success) {
		perror("nmsg_io_add_buf");
		exit(1);
	}
	if (c->debug >= 1)
		fprintf(stderr, "%s: nmsg file output: %s\n", argv_program,
			fname);
	c->n_outputs += 1;
}

static void
add_pres_input(nmsgtool_ctx *c, nmsg_pbmod mod, const char *fname) {
	nmsg_pres pres;
	nmsg_res res;

	pres = nmsg_input_open_pres(open_rfile(fname), c->vendor, c->msgtype);
	res = nmsg_io_add_pres(c->io, pres, mod, NULL);
	if (res != nmsg_res_success) {
		perror("nmsg_io_add_pres_input");
		exit(1);
	}
	if (c->debug >= 1)
		fprintf(stderr, "%s: nmsg pres input: %s\n", argv_program,
			fname);
	c->n_inputs += 1;
}

static void
add_pres_output(nmsgtool_ctx *c, nmsg_pbmod mod, const char *fname) {
	nmsg_pres pres;
	nmsg_res res;

	pres = nmsg_output_open_pres(open_wfile(fname));
	res = nmsg_io_add_pres(c->io, pres, mod, NULL);
	if (res != nmsg_res_success) {
		perror("nmsg_io_add_pres_output");
		exit(1);
	}
	if (c->debug >= 1)
		fprintf(stderr, "%s: nmsg pres output: %s\n", argv_program,
			fname);
	c->n_outputs += 1;
}

static int
getsock(nmsgtool_sockaddr *su, const char *addr, const char *rem,
	unsigned *rate, unsigned *freq)
{
	char *p, *t, *tmp, *tmp2;
	unsigned port, pf;

	tmp = strdup(addr);
	if (rem != NULL)
		t = tmp2 = strdup(rem);
	else
		t = tmp2 = NULL;
	p = strchr(tmp, '/');
	memset(su, 0, sizeof *su);
	if (p == NULL) {
		fprintf(stderr, "getsock: no slash found\n");
		free(tmp);
		return (-1);
	}
	*p++ = '\0';
	port = strtoul(p, NULL, 0);
	if (t && *t == ',' && rate != NULL && freq != NULL) {
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
		} else {
			*freq = DEFAULT_FREQ;
		}
		*rate = t_rate;
	}
	if (t && (*t != '\0' || port == 0)) {
		fprintf(stderr, "getsock: invalid port number\n");
		free(tmp);
		return (-1);
	}
	if (inet_pton(AF_INET6, tmp, &su->s6.sin6_addr)) {
#if HAVE_SA_LEN
		su->s6.sin6_len = sizeof(su->s6);
#endif
		su->s6.sin6_family = AF_INET6;
		su->s6.sin6_port = htons(port);
		pf = PF_INET6;
	} else if (inet_pton(AF_INET, tmp, &su->s4.sin_addr)) {
#if HAVE_SA_LEN
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
	free(tmp2);
	return (pf);
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
