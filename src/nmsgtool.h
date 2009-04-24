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

#include "argv.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdbool.h>

#include <nmsg.h>

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
	char		*set_source_str, *set_operator_str, *set_group_str;

	/* state */
	argv_t		*args;
	int		n_inputs, n_outputs;
	nmsg_io_t	io;
	nmsg_pbmodset_t	ms;
	unsigned	msgtype, vendor;
	unsigned	set_source, set_operator, set_group;
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
#define CHALIAS_FILE	NMSG_ETCDIR "/nmsgtool.chalias"

/* Function prototypes. */

char *unescape(const char *str);
int open_rfile(const char *fname);
int open_wfile(const char *fname);
void usage(const char *msg);

#endif /* NMSGTOOL_H */
