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
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nmsg.h"
#include "nmsgtool_sock.h"

/* Crack a socket descriptor (addr/port).
 */
int
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
		su->s6.sin6_len = sizeof su->s6;
#endif
		su->s6.sin6_family = AF_INET6;
		su->s6.sin6_port = htons(port);
		pf = PF_INET6;
	} else if (inet_pton(AF_INET, tmp, &su->s4.sin_addr)) {
#if HAVE_SA_LEN
		su->s4.sin_len = sizeof su->s4;
#endif
		su->s4.sin_family = AF_INET;
		su->s4.sin_port = htons(port);
		pf = PF_INET;
	} else {
		fprintf(stderr, "getsock: addr is not valid inet or inet6\n");
		free(tmp);
		return (-1);
	}
	return (pf);
}

void setup_socksink(nmsgtool_ctx *ctx, const char *ss) {
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
		nmsgtool_bufsink *bufsink;
		static const int on = 1;

		bufsink = calloc(1, sizeof(*bufsink));
		assert(bufsink != NULL);
		ISC_LINK_INIT(bufsink, link);

		asprintf(&spec, "%*.*s/%d",
			 pl, pl, ss, pn);
		pf = getsock(&su, spec, &bufsink->rate, &bufsink->freq);
		free(spec);
		if (pf < 0)
			usage("bad -s socket");
		s = socket(pf, SOCK_DGRAM, 0);
		if (s < 0) {
			perror("socket");
			exit(1);
		}
		if (setsockopt(s, SOL_SOCKET, SO_BROADCAST,
			       &on, sizeof on) < 0)
		{
			perror("setsockopt(SO_BROADCAST)");
			exit(1);
		}
		len = 32 * 1024;
		if (setsockopt(s, SOL_SOCKET, SO_SNDBUF,
			       &len, sizeof len) < 0)
		{
			perror("setsockopt(SO_SNDBUF)");
			exit(1);
		}
		if (connect(s, &su.sa,
			    NMSGTOOL_SA_LEN(su.sa)) < 0)
		{
			perror("connect");
			exit(1);
		}

		bufsink->buf = nmsg_input_open_fd(s);
		ISC_LIST_APPEND(ctx->bufsinks, bufsink, link);
		ctx->nsinks += 1;
	}

}
