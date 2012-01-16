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

/* Data structures. */

#ifndef NMSGTOOL_H
#define NMSGTOOL_H

#include "nmsg_port_net.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdbool.h>

#include <nmsg.h>

#include "argv.h"

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

#define DEFAULT_FREQ	100

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
void pidfile_write(FILE *);
void process_args(nmsgtool_ctx *);
void setup_nmsg_input(nmsgtool_ctx *, nmsg_input_t);
void setup_nmsg_output(nmsgtool_ctx *, nmsg_output_t);
void usage(const char *);

#endif /* NMSGTOOL_H */
