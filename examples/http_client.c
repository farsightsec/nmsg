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

/* Import. */

#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/output.h>
#include <nmsg/payload.h>
#include <nmsg/pbmod.h>
#include <nmsg/pbmodset.h>
#include <nmsg/time.h>

/* Data structures. */

union nmsgtool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
};
typedef union nmsgtool_sockaddr nmsgtool_sockaddr;

/* Data. */

/* Macros. */

#define MODULE_DIR	"/usr/local/lib/nmsg"
#define MODULE_VENDOR	"ISC"
#define MODULE_MSGTYPE	"http"

#define DST_ADDRESS	"127.0.0.1"
#define DST_PORT	8430
#define DST_MTU		1280

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

/* Forward. */

void fail(const char *str);

/* Functions. */

int main(void) {
	Nmsg__NmsgPayload *np;
	int s, len;
	nmsg_buf buf;
	nmsg_pbmod mod;
	nmsg_pbmodset ms;
	nmsg_res res;
	nmsgtool_sockaddr su;
	size_t sz;
	uint8_t *pbuf;
	unsigned vid, msgtype;
	void *clos;
	struct timespec ts;

	res = nmsg_res_success;

	/* set dst address / port */
	if (inet_pton(AF_INET, DST_ADDRESS, &su.s4.sin_addr)) {
#ifdef HAVE_SA_LEN
		su.s4.sin_len = sizeof(su.s4);
#endif
		su.s4.sin_family = AF_INET;
		su.s4.sin_port = htons(DST_PORT);
	} else {
		perror("inet_pton");
		exit(1);
	}

	/* open socket */
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		exit(1);
	}

	/* set socket options */
	len = 32 * 1024;
	Setsockopt(s, SOL_SOCKET, SO_SNDBUF, len);
	if (connect(s, &su.sa, NMSGTOOL_SA_LEN(su.sa)) < 0) {
		perror("connect");
		exit(1);
	}

	/* create nmsg output buf */
	buf = nmsg_output_open_sock(s, DST_MTU);
	if (buf == NULL)
		fail("unable to nmsg_output_open_sock()");

	/* load modules */
	ms = nmsg_pbmodset_init(MODULE_DIR, 0);
	if (ms == NULL)
		fail("unable to nmsg_pbmodset_init()");

	/* open handle to the linkpair module */
	vid = nmsg_pbmodset_vname2vid(ms, MODULE_VENDOR);
	msgtype = nmsg_pbmodset_mname2msgtype(ms, vid, MODULE_MSGTYPE);
	mod = nmsg_pbmodset_lookup(ms, vid, msgtype);
	if (mod == NULL)
		fail("unable to acquire module handle");

	/* initialize module */
	clos = nmsg_pbmod_init(mod, 0);

	/* create pbuf */

	int port = 42;
	int port2 = 17;
	char request[] = "GET / HTTP/1.0\n";

	nmsg_pbmod_field2pbuf(mod, clos, "type", (const unsigned char *) "sinkhole",
			      sizeof("sinkhole"), NULL, NULL);
	nmsg_pbmod_field2pbuf(mod, clos, "srcip", (const unsigned char *) "127.42.42.42",
			      sizeof("127.42.42.42"), NULL, NULL);
	nmsg_pbmod_field2pbuf(mod, clos, "dstip", (const unsigned char *) "127.17.17.17",
			      sizeof("127.42.42.42"), NULL, NULL);
	nmsg_pbmod_field2pbuf(mod, clos, "srchost", (const unsigned char *) "aaoeuu.aoeu",
			      sizeof("aaoeuu.aoeu"), NULL, NULL);
	nmsg_pbmod_field2pbuf(mod, clos, "srcport", (const unsigned char *) &port,
			      2, NULL, NULL);
	nmsg_pbmod_field2pbuf(mod, clos, "dstport", (const unsigned char *) &port2,
			      2, NULL, NULL);
	nmsg_pbmod_field2pbuf(mod, clos, "request", (const unsigned char *) request,
			      strlen(request) + 1, NULL, NULL);
	res = nmsg_pbmod_field2pbuf(mod, clos, NULL, NULL, 0, &pbuf, &sz);
	assert(res == nmsg_res_pbuf_ready);

	nmsg_time_get(&ts);
	np = nmsg_payload_make(pbuf, sz, vid, msgtype, &ts);
	if (np == NULL)
		fail("nmsg_payload_make failed");
	nmsg_output_append(buf, np);

	/* finalize module */
	nmsg_pbmod_fini(mod, clos);

	/* close nmsg output buf */
	nmsg_output_close(&buf);

	/* unload modules */
	nmsg_pbmodset_destroy(&ms);

	return (res);
}

void fail(const char *str) {
	fprintf(stderr, "%s\n", str);
	exit(1);
}
