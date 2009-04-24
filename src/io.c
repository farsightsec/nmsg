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

#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "kickfile.h"
#include "nmsgtool.h"

static const int on = 1;

void
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

void
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

void
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

void
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

void
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

void
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

void
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

void
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
					       c->ms);
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, (void *) kf);
	} else {
		output = nmsg_output_open_pres(open_wfile(fname), c->ms);
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
