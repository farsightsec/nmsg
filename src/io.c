/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2008-2019, 2021 by Farsight Security, Inc.
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#ifdef HAVE_LIBZMQ
# include <zmq.h>
#endif /* HAVE_LIBZMQ */

#ifdef HAVE_LIBRDKAFKA
#include <librdkafka/rdkafka.h>
#endif /* HAVE_LIBRDKAFKA */

#include "kickfile.h"
#include "nmsgtool.h"

#include "libmy/my_alloc.h"

static const int on = 1;

static const char *
_strip_prefix_if_exists(const char *str, const char *prefix) {
	if (strstr(str, prefix) != str)
		return NULL;

	return str + strlen(prefix);
}

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
		int pf, s;
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

#ifdef __linux__
# ifdef SO_RCVBUFFORCE
		if (geteuid() == 0) {
			int rcvbuf = 16777216;
			if (setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE,
				       &rcvbuf, sizeof(rcvbuf)) < 0)
			{
				if (c->debug >= 2) {
					fprintf(stderr,
						"%s: setsockopt(SO_RCVBUFFORCE) failed: %s\n",
						argv_program, strerror(errno));
				}
			}
		}
# endif
#endif

		if (bind(s, &su.sa, NMSGTOOL_SA_LEN(su.sa)) < 0) {
			perror("bind");
			exit(1);
		}
		input = nmsg_input_open_sock(s);
		if (input == NULL) {
			fprintf(stderr, "%s: nmsg_input_open_sock() failed\n",
				argv_program);
			exit(1);
		}
		setup_nmsg_input(c, input);
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
	nmsg_rate_t nr = NULL;
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
		if (output == NULL) {
			fprintf(stderr, "%s: nmsg_output_open_sock() failed\n",
				argv_program);
			exit(1);
		}
		setup_nmsg_output(c, output);
		if (rate > 0) {
			if (nr == NULL) {
				nr = nmsg_rate_init(rate, freq);
				assert(nr != NULL);
			}
			nmsg_output_set_rate(output, nr);
		}
		if (c->kicker != NULL) {
			res = nmsg_io_add_output(c->io, output, (void *) -1);
		} else {
			res = nmsg_io_add_output(c->io, output, NULL);
		}
		if (res != nmsg_res_success) {
			fprintf(stderr, "%s: nmsg_io_add_output() failed\n",
				argv_program);
			exit(1);
		}
		c->n_outputs += 1;
	}
}

#if (defined HAVE_JSON_C) && (defined HAVE_LIBRDKAFKA)
static void
_add_kafka_json_input(nmsgtool_ctx *c, const char *str_address) {
	nmsg_input_t input;
	nmsg_res res;

	input = nmsg_input_open_kafka_json(str_address);
	if (input == NULL) {
		fprintf(stderr, "%s: nmsg_input_open_kafka_json() failed\n",
			argv_program);
		exit(1);
	}
	setup_nmsg_input(c, input);
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg Kafka json input: %s\n", argv_program,
			str_address);
	c->n_inputs += 1;
}
#else /* (defined HAVE_JSON_C) && (defined HAVE_LIBRDKAFKA) */
static void
_add_kafka_json_input(nmsgtool_ctx *c __attribute__((unused)),
		      const char *str_address __attribute__((unused))) {
	fprintf(stderr, "%s: Error: compiled without librdkafka or json-c support\n",
		argv_program);
	exit(EXIT_FAILURE);
}
#endif /* (defined HAVE_JSON_C) && (defined HAVE_LIBRDKAFKA) */

#ifdef HAVE_LIBRDKAFKA
static void
_add_kafka_json_output(nmsgtool_ctx *c, const char *str_address) {
	nmsg_output_t output;
	nmsg_res res;

	output = nmsg_output_open_kafka_json(str_address, c->kafka_key_field);
	if (output == NULL) {
		fprintf(stderr, "%s: nmsg_output_open_kafka_json() failed\n",
			argv_program);
		exit(1);
	}
	setup_nmsg_output(c, output);
	if (c->kicker != NULL)
		res = nmsg_io_add_output(c->io, output, (void *) -1);
	else
		res = nmsg_io_add_output(c->io, output, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_output() failed\n", argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg Kafka json output: %s\n", argv_program,
			str_address);
	c->n_outputs += 1;
}
#else /* HAVE_LIBRDKAFKA */
static void
_add_kafka_json_output(nmsgtool_ctx *c __attribute__((unused)),
		       const char *str_address __attribute__((unused))) {
	fprintf(stderr, "%s: Error: compiled without librdkafka or json-c support\n",
		argv_program);
	exit(EXIT_FAILURE);
}
#endif /* HAVE_LIBRDKAFKA */

#ifdef HAVE_LIBRDKAFKA
static void
_add_kafka_nmsg_input(nmsgtool_ctx *c, const char *str_address) {
	nmsg_res res;
	nmsg_input_t input;

	input = nmsg_input_open_kafka_endpoint(str_address);
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg Kafka input: %s\n", argv_program, str_address);
	if (input == NULL) {
		fprintf(stderr, "%s: nmsg_input_open_kafka_endpoint() failed\n", argv_program);
		exit(1);
	}
	setup_nmsg_input(c, input);
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n", argv_program);
		exit(1);
	}
	c->n_inputs += 1;
}

static void
_add_kafka_nmsg_output(nmsgtool_ctx *c, const char *str_address) {
	nmsg_res res;
	nmsg_output_t output;

	output = nmsg_output_open_kafka_endpoint(str_address, NMSG_WBUFSZ_JUMBO);
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg Kafka output: %s\n", argv_program, str_address);
	if (output == NULL) {
		fprintf(stderr, "%s: nmsg_output_open_kafka_endpoint() failed\n", argv_program);
		exit(1);
	}
	setup_nmsg_output(c, output);
	if (c->kicker != NULL)
		res = nmsg_io_add_output(c->io, output, (void *) -1);
	else
		res = nmsg_io_add_output(c->io, output, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_output() failed\n", argv_program);
		exit(1);
	}
	c->n_outputs += 1;
}
#else /* HAVE_LIBRDKAFKA */
static void
_add_kafka_nmsg_input(nmsgtool_ctx *c __attribute__((unused)),
		      const char *str_address __attribute__((unused)))
{
	fprintf(stderr, "%s: Error: compiled without librdkafka support\n",
			argv_program);
	exit(EXIT_FAILURE);
}

static void
_add_kafka_nmsg_output(nmsgtool_ctx *c __attribute__((unused)),
		       const char *str_address __attribute__((unused)))
{
	fprintf(stderr, "%s: Error: compiled without librdkafka support\n",
		argv_program);
	exit(EXIT_FAILURE);
}
#endif /* HAVE_LIBRDKAFKA */

void
add_kafka_input(nmsgtool_ctx *c, const char *str_address) {
	const char *addr = _strip_prefix_if_exists(str_address, "nmsg:");
	if (addr != NULL) {
		_add_kafka_nmsg_input(c, addr);
		return;
	}
#ifdef HAVE_JSON_C
	addr = _strip_prefix_if_exists(str_address, "json:");
	if (addr != NULL) {
		_add_kafka_json_input(c, addr);
		return;
	}
	fprintf(stderr, "%s: Error: nmsg or json protocol must be set for Kafka topic\n",
		argv_program);
#else /* HAVE_JSON_C */
	fprintf(stderr, "%s: Error: nmsg protocol must be set for Kafka topic\n",
		argv_program);
#endif /* HAVE_JSON_C */
	exit(EXIT_FAILURE);
}

void
add_kafka_output(nmsgtool_ctx *c, const char *str_address) {
	const char *addr = _strip_prefix_if_exists(str_address, "nmsg:");
	if (addr != NULL) {
		_add_kafka_nmsg_output(c, addr);
		return;
	}
#ifdef HAVE_JSON_C
	addr = _strip_prefix_if_exists(str_address, "json:");
	if (addr != NULL) {
		_add_kafka_json_output(c, addr);
		return;
	}
	fprintf(stderr, "%s: Error: nmsg or json protocol must be set for Kafka topic\n",
		argv_program);
#else /* HAVE_JSON_C */
	fprintf(stderr, "%s: Error: nmsg protocol must be set for Kafka topic\n",
		argv_program);
#endif /* HAVE_JSON_C */
	exit(EXIT_FAILURE);
}

#ifdef HAVE_LIBZMQ
void
add_zsock_input(nmsgtool_ctx *c, const char *str_socket) {
	nmsg_res res;
	nmsg_input_t input;

	input = nmsg_input_open_zmq_endpoint(c->zmq_ctx, str_socket);
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg ZMQ input: %s\n", argv_program, str_socket);
	if (input == NULL) {
		fprintf(stderr, "%s: nmsg_input_open_zmq_endpoint() failed\n", argv_program);
		exit(1);
	}
	setup_nmsg_input(c, input);
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n", argv_program);
		exit(1);
	}
	c->n_inputs += 1;
}
#else /* HAVE_LIBZMQ */
void
add_zsock_input(nmsgtool_ctx *c __attribute__((unused)),
		const char *str_socket __attribute__((unused)))
{
	fprintf(stderr, "%s: Error: compiled without libzmq support\n",
		argv_program);
	exit(EXIT_FAILURE);
}
#endif /* HAVE_LIBZMQ */

#ifdef HAVE_LIBZMQ
void
add_zsock_output(nmsgtool_ctx *c, const char *str_socket) {
	nmsg_res res;
	nmsg_output_t output;

	output = nmsg_output_open_zmq_endpoint(c->zmq_ctx, str_socket, NMSG_WBUFSZ_JUMBO);
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg ZMQ output: %s\n", argv_program, str_socket);
	if (output == NULL) {
		fprintf(stderr, "%s: nmsg_output_open_zmq_endpoint() failed\n", argv_program);
		exit(1);
	}
	setup_nmsg_output(c, output);
	if (c->kicker != NULL)
		res = nmsg_io_add_output(c->io, output, (void *) -1);
	else
		res = nmsg_io_add_output(c->io, output, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_output() failed\n", argv_program);
		exit(1);
	}
	c->n_outputs += 1;
}
#else /* HAVE_LIBZMQ */
void
add_zsock_output(nmsgtool_ctx *c __attribute__((unused)),
		 const char *str_socket __attribute__((unused)))
{
	fprintf(stderr, "%s: Error: compiled without libzmq support\n",
		argv_program);
	exit(EXIT_FAILURE);
}
#endif /* HAVE_LIBZMQ */

void
add_file_input(nmsgtool_ctx *c, const char *fname) {
	nmsg_input_t input;
	nmsg_res res;

	input = nmsg_input_open_file(open_rfile(fname));
	if (input == NULL) {
		fprintf(stderr, "%s: nmsg_input_open_file() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg file input: %s\n", argv_program,
			fname);
	if (c->byte_rate > 0) {
		nmsg_input_set_byte_rate(input, (size_t) c->byte_rate);
		if (c->debug >= 4)
			fprintf(stderr, "%s: %s ingress rate limit set to %u bytes/sec\n",
				argv_program, fname, c->byte_rate);
	}
	setup_nmsg_input(c, input);
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
			argv_program);
		exit(1);
	}
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
		if (output == NULL) {
			fprintf(stderr, "%s: nmsg_output_open_file() failed\n",
				argv_program);
			exit(1);
		}
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, (void *) kf);
		c->stats_user = kf;
	} else {
		output = nmsg_output_open_file(open_wfile(fname),
					       NMSG_WBUFSZ_MAX);
		if (output == NULL) {
			fprintf(stderr, "%s: nmsg_output_open_file() failed\n",
				argv_program);
			exit(1);
		}
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
add_pcapfile_input(nmsgtool_ctx *c, nmsg_msgmod_t mod, const char *fname) {
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
		exit(1);
	}
	if (c->bpfstr != NULL) {
		res = nmsg_pcap_input_setfilter(pcap, c->bpfstr);
		if (res != nmsg_res_success) {
			fprintf(stderr, "%s: nmsg_pcap_input_setfilter() failed\n",
				argv_program);
			exit(1);
		}
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
add_pcapif_input(nmsgtool_ctx *c, nmsg_msgmod_t mod, const char *arg) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char *iface, *ssnaplen, *spromisc;
	char *saveptr = NULL;
	char *tmp;
	int snaplen = NMSG_DEFAULT_SNAPLEN;
	int promisc = 0;
	int rc;
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

#ifdef HAVE_PCAP_CREATE
	phandle = pcap_create(iface, errbuf);
	if (phandle == NULL) {
		fprintf(stderr, "%s: unable to add pcap interface input "
			"%s: %s\n", argv_program, iface, errbuf);
		exit(1);
	}

	rc = pcap_set_promisc(phandle, promisc);
	if (rc != 0) {
		fprintf(stderr, "%s: pcap_set_promisc() failed\n", argv_program);
		exit(1);
	}

	rc = pcap_set_snaplen(phandle, snaplen);
	if (rc != 0) {
		fprintf(stderr, "%s: pcap_set_snaplen() failed\n", argv_program);
		exit(1);
	}

	rc = pcap_set_timeout(phandle, 1000);
	if (rc != 0) {
		fprintf(stderr, "%s: pcap_set_timeout() failed\n", argv_program);
		exit(1);
	}

	rc = pcap_set_buffer_size(phandle, 16777216);
	if (rc != 0) {
		fprintf(stderr, "%s: pcap_set_buffer_size() failed\n", argv_program);
		exit(1);
	}

	rc = pcap_activate(phandle);
	if (rc != 0) {
		fprintf(stderr, "%s: pcap_activate() failed: %d\n", argv_program, rc);
		exit(1);
	}
#else
	phandle = pcap_open_live(iface, snaplen, promisc, 1000, errbuf);
	if (phandle == NULL) {
		fprintf(stderr, "%s: unable to add pcap interface input "
			"%s: %s\n", argv_program, iface, errbuf);
		exit(1);
	}
#endif

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
		exit(1);
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
add_pres_input(nmsgtool_ctx *c, nmsg_msgmod_t mod, const char *fname) {
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

		output = nmsg_output_open_pres(open_wfile(kf->tmpname));
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, (void *) kf);
		c->stats_user = kf;
	} else {
		output = nmsg_output_open_pres(open_wfile(fname));
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

#ifdef HAVE_JSON_C
void
add_json_input(nmsgtool_ctx *c, const char *fname) {
	nmsg_input_t input;
	nmsg_res res;

	input = nmsg_input_open_json(open_rfile(fname));
	res = nmsg_io_add_input(c->io, input, NULL);
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_input() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg json input: %s\n", argv_program,
			fname);
	c->n_inputs += 1;
}
#else /* HAVE_JSON_C */
void
add_json_input(__attribute__((unused)) nmsgtool_ctx *c,
	       __attribute__((unused)) const char *fname) {
	fprintf(stderr, "%s: Error: compiled without json-c support\n",
		argv_program);
	exit(EXIT_FAILURE);
}
#endif /* HAVE_JSON_C */

void
add_json_output(nmsgtool_ctx *c, const char *fname) {
	nmsg_output_t output;
	nmsg_res res;

	if (c->kicker != NULL) {
		struct kickfile *kf;
		kf = calloc(1, sizeof(*kf));
		assert(kf != NULL);

		kf->cmd = c->kicker;
		kf->basename = strdup(fname);
		kf->suffix = strdup(".json");
		kickfile_rotate(kf);

		output = nmsg_output_open_json(open_wfile(kf->tmpname));
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, (void *) kf);
		c->stats_user = kf;
	} else {
		output = nmsg_output_open_json(open_wfile(fname));
		setup_nmsg_output(c, output);
		res = nmsg_io_add_output(c->io, output, NULL);
	}
	if (res != nmsg_res_success) {
		fprintf(stderr, "%s: nmsg_io_add_output() failed\n",
			argv_program);
		exit(1);
	}
	if (c->debug >= 2)
		fprintf(stderr, "%s: nmsg json output: %s\n", argv_program,
			fname);
	c->n_outputs += 1;
}

void
add_filter_module(nmsgtool_ctx *c, const char *args) {
	nmsg_res res;
	char *tmp = NULL;
	char *saveptr = NULL;
	char *mod_name = NULL;
	char *mod_param = NULL;
	size_t len_mod_param = 0;

	/* Parse the arguments. */
	tmp = my_strdup(args);
	mod_name = strtok_r(tmp, ",", &saveptr);
	mod_param = strtok_r(NULL, "", &saveptr);
	if (mod_param != NULL) {
		len_mod_param = strlen(mod_param) + 1;
	}

	/* Load the filter module. */
	if (c->debug >= 2)
		fprintf(stderr, "%s: adding filter module %s\n", argv_program, args);
	res = nmsg_io_add_filter_module(c->io, mod_name, mod_param, len_mod_param);
	if (res != nmsg_res_success) {
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg_io_add_filter_module() failed for %s,%s: %s (%d)\n",
				argv_program, mod_name, mod_param, nmsg_res_lookup(res), res);
		exit(EXIT_FAILURE);
	}

	my_free(tmp);
}
