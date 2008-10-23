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

#include "config.h"
#include "nmsg_port.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "nmsg.h"
#include "nmsgtool.h"
#include "nmsgtool_buf.h"

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

/* Data structures. */

union nmsgtool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};
typedef union nmsgtool_sockaddr nmsgtool_sockaddr;

static const int on = 1;

/* Forward. */

static int getsock(nmsgtool_sockaddr *, const char *addr, unsigned *rate,
		   unsigned *freq);
static int open_rfile(const char *);
static int open_wfile(const char *);

/* Export. */

void
nmsgtool_add_sock_input(nmsgtool_ctx *c, const char *ss) {
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
		pf = getsock(&su, spec, NULL, NULL);
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

void
nmsgtool_add_sock_output(nmsgtool_ctx *c, const char *ss) {
	char *t;
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
	for (pn = pa; pn <= pz; pn++) {
		char *spec;
		int len, pf, s;
		nmsgtool_sockaddr su;
		nmsg_buf buf;
		nmsg_res res;

		asprintf(&spec, "%*.*s/%d",
			 pl, pl, ss, pn);
		if (c->debug > 0)
			fprintf(stderr, "%s: nmsg socket output: %s\n",
				argv_program, spec);
		pf = getsock(&su, spec, NULL, NULL);
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
		buf = nmsg_output_open(s, c->mtu);
		res = nmsg_io_add_buf(c->io, buf, NULL);
		if (res != nmsg_res_success) {
			perror("nmsg_io_add_buf");
			exit(1);
		}
		c->n_outputs += 1;
	}
}

void
nmsgtool_add_file_input(nmsgtool_ctx *c, const char *fname) {
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

void
nmsgtool_add_file_output(nmsgtool_ctx *c, const char *fname) {
	nmsg_buf buf;
	nmsg_res res;

	buf = nmsg_output_open(open_wfile(fname), nmsg_wbufsize_max);
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

void
nmsgtool_add_pres_input(nmsgtool_ctx *c, nmsg_pbmod mod, const char *fname) {
	nmsg_res res;

	res = nmsg_io_add_pres_input(c->io, mod, open_rfile(fname), NULL);
	if (res != nmsg_res_success) {
		perror("nmsg_io_add_pres_input");
		exit(1);
	}
	if (c->debug >= 1)
		fprintf(stderr, "%s: nmsg pres input: %s\n", argv_program,
			fname);
	c->n_inputs += 1;
}

void
nmsgtool_add_pres_output(nmsgtool_ctx *c, nmsg_pbmod mod, const char *fname) {
	nmsg_res res;

	res = nmsg_io_add_pres_output(c->io, mod, open_wfile(fname), NULL);
	if (res != nmsg_res_success) {
		perror("nmsg_io_add_pres_output");
		exit(1);
	}
	if (c->debug >= 1)
		fprintf(stderr, "%s: nmsg pres output: %s\n", argv_program,
			fname);
	c->n_outputs += 1;
}

#if 0
void
nmsgtool_inputs_destroy(nmsgtool_ctx *c) {
	nmsgtool_bufinput *bufin, *bufin_next;

	bufin = ISC_LIST_HEAD(c->inputs);
	while (bufin != NULL) {
		bufin_next = ISC_LIST_NEXT(bufin, link);
		nmsg_output_close(&bufin->buf);
		ISC_LIST_UNLINK(c->inputs, bufin, link);
		free(bufin);
		bufin = bufin_next;
		c->n_inputs -= 1;
	}
}

void
nmsgtool_outputs_destroy(nmsgtool_ctx *c) {
	nmsgtool_bufoutput *bufout, *bufout_next;

	bufout = ISC_LIST_HEAD(c->outputs);
	while (bufout != NULL) {
		bufout_next = ISC_LIST_NEXT(bufout, link);
		nmsg_output_close(&bufout->buf);
		ISC_LIST_UNLINK(c->outputs, bufout, link);
		free(bufout);
		bufout = bufout_next;
		c->n_outputs -= 1;
	}
}
#endif

/* Crack a socket descriptor (addr/port).
 */
static int
getsock(nmsgtool_sockaddr *su, const char *addr, unsigned *rate,
	unsigned *freq)
{
	char *p, *t, *tmp;
	unsigned port, pf;

	tmp = strdup(addr);
	p = strchr(tmp, '/');
	memset(su, 0, sizeof *su);
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
