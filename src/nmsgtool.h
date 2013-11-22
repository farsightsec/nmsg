/*
 * Copyright (c) 2008-2013 by Farsight Security, Inc.
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

#ifdef HAVE_LIBXS
# include <xs/xs.h>
#endif /* HAVE_LIBXS */

#include "librsf/argv.h"

union nmsgtool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};
typedef union nmsgtool_sockaddr nmsgtool_sockaddr;

typedef struct {
	/* parameters */
	argv_array_t	r_nmsg, r_pres, r_sock, r_xsock, r_channel, r_xchannel;
	argv_array_t	r_pcapfile, r_pcapif;
	argv_array_t	w_nmsg, w_pres, w_sock, w_xsock;
	bool		help, mirror, unbuffered, zlibout, daemon, version;
	char		*endline, *kicker, *mname, *vname, *bpfstr;
	int		debug;
	unsigned	mtu, count, interval, rate, freq, byte_rate;
	char		*set_source_str, *set_operator_str, *set_group_str;
	char		*get_source_str, *get_operator_str, *get_group_str;
	char		*pidfile;
	char		*username;

	/* state */
	char		*endline_str;
	int		n_inputs, n_outputs;
	nmsg_io_t	io;
#ifdef HAVE_LIBXS
	void		*xs_ctx;
#endif /* HAVE_LIBXS */
	unsigned	vid, msgtype;
	unsigned	set_source, set_operator, set_group;
	unsigned	get_source, get_operator, get_group;
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
void add_sock_input(nmsgtool_ctx *, const char *);
void add_sock_output(nmsgtool_ctx *, const char *);
void add_xsock_input(nmsgtool_ctx *, const char *);
void add_xsock_output(nmsgtool_ctx *, const char *);
void pidfile_write(FILE *);
void process_args(nmsgtool_ctx *);
void setup_nmsg_input(nmsgtool_ctx *, nmsg_input_t);
void setup_nmsg_output(nmsgtool_ctx *, nmsg_output_t);
void usage(const char *);

#endif /* NMSGTOOL_H */
