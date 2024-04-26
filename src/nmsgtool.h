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

/* Data structures. */

#ifndef NMSGTOOL_H
#define NMSGTOOL_H

#include "nmsg_port_net.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdbool.h>

#include <nmsg.h>

#ifdef HAVE_LIBZMQ
# include <zmq.h>
#endif /* HAVE_LIBZMQ */

#ifdef HAVE_LIBRDKAFKA
#include <librdkafka/rdkafka.h>
#endif /* HAVE_LIBRDKAFKA */

#include "libmy/argv.h"

#define NMSG_KAFKA_TIMEOUT 1000

union nmsgtool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};
typedef union nmsgtool_sockaddr nmsgtool_sockaddr;

typedef struct {
	/* parameters */
	argv_array_t	filters;
	argv_array_t	r_nmsg, r_pres, r_kafka, r_sock, r_zsock, r_channel, r_zchannel, r_json;
	argv_array_t	r_pcapfile, r_pcapif;
	argv_array_t	w_nmsg, w_pres, w_sock, w_kafka, w_zsock, w_json;
	bool		help, mirror, unbuffered, zlibout, daemon, version, interval_randomized;
	char		*endline, *kicker, *mname, *vname, *bpfstr, *filter_policy;
	int		debug, signal;
	unsigned	mtu, count, interval, rate, freq, byte_rate;
	char		*set_source_str, *set_operator_str, *set_group_str;
	char		*get_source_str, *get_operator_str, *get_group_str;
	char		*pidfile;
	char		*username;

	/* state */
	char		*endline_str;
	int		n_inputs, n_outputs;
	nmsg_io_t	io;
#ifdef HAVE_LIBZMQ
	void		*zmq_ctx;
#endif /* HAVE_LIBZMQ */
	unsigned	vid, msgtype;
	unsigned	set_source, set_operator, set_group;
	unsigned	get_source, get_operator, get_group;

	/*
	 * Selected output for which we will report statistics on close events.
	 *
	 * At a sufficient debug level, nmsgtool will report input statistics
	 * at exit. If a count limit or time interval is specified with a
	 * kicker script, nmsgtool will also report statistics periodically
	 * throughout its run.
	 *
	 * The latter reports are driven by close events to a selected output,
	 * identified by the user data passed to nmsg_io_add_output.
	 */
	void		*stats_user;
} nmsgtool_ctx;

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

#define DEFAULT_FREQ	10

/* Function prototypes. */

bool daemonize(void);
char *unescape(const char *);
FILE *pidfile_open(const char *pidfile);
int getsock(nmsgtool_sockaddr *, const char *, unsigned *, unsigned *);
int open_rfile(const char *);
int open_wfile(const char *);
void add_file_input(nmsgtool_ctx *, const char *);
void add_file_output(nmsgtool_ctx *, const char *);
void add_pcapfile_input(nmsgtool_ctx *, nmsg_msgmod_t, const char *);
void add_pcapif_input(nmsgtool_ctx *, nmsg_msgmod_t, const char *);
void add_pres_input(nmsgtool_ctx *, nmsg_msgmod_t, const char *);
void add_pres_output(nmsgtool_ctx *, const char *);
void add_kafka_json_input(nmsgtool_ctx *, const char *);
void add_kafka_json_output(nmsgtool_ctx *, const char *);
void add_json_input(nmsgtool_ctx *, const char *);
void add_json_output(nmsgtool_ctx *, const char *);
void add_sock_input(nmsgtool_ctx *, const char *);
void add_sock_output(nmsgtool_ctx *, const char *);
void add_kafka_input(nmsgtool_ctx *, const char *);
void add_kafka_output(nmsgtool_ctx *, const char *);
void add_zsock_input(nmsgtool_ctx *, const char *);
void add_zsock_output(nmsgtool_ctx *, const char *);
void add_filter_module(nmsgtool_ctx *, const char *);
void pidfile_write(FILE *);
void process_args(nmsgtool_ctx *);
void setup_nmsg_input(nmsgtool_ctx *, nmsg_input_t);
void setup_nmsg_output(nmsgtool_ctx *, nmsg_output_t);
void usage(const char *);

#endif /* NMSGTOOL_H */
