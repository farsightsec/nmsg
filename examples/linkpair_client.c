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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <nmsg.h>
#include <nmsg/isc/nmsgpb_isc_linkpair.h>

/* Data. */

static char http[] = "http://sie.isc.org/";
static char https[] = "https://sie.isc.org/";
static char headers[] =
"HTTP/1.1 200 OK\n"
"Date: Thu, 20 Nov 2008 01:00:32 GMT\n"
"Server: Apache/2.2.9 (FreeBSD) mod_ssl/2.2.9 OpenSSL/0.9.8g mod_perl/2.0.4 Perl/v5.8.8\n"
"Cache-Control: no-cache\n"
"Connection: close\n"
"Content-Type: text/html\n"
;

/* Macros. */

#define DEBUG_LEVEL	0

#define MODULE_DIR	"/usr/local/lib/nmsg"

#define DST_ADDRESS	"127.0.0.1"
#define DST_PORT	8430
#define DST_MTU		1280

/* Forward. */

void fail(const char *str);

/* Functions. */

int main(void) {
	Nmsg__Isc__Linkpair *lp;
	int nmsg_sock;
	nmsg_output_t output;
	nmsg_pbmod_t mod;
	nmsg_pbmodset_t ms;
	nmsg_res res;
	struct sockaddr_in nmsg_sockaddr;
	unsigned i;
	void *clos;

	res = nmsg_res_success;

        /* set dst address / port */
        if (inet_pton(AF_INET, DST_ADDRESS, &nmsg_sockaddr.sin_addr)) {
                nmsg_sockaddr.sin_family = AF_INET;
                nmsg_sockaddr.sin_port = htons(DST_PORT);
        } else {
                perror("inet_pton");
                exit(1);
        }

        /* open socket */
        nmsg_sock = socket(PF_INET, SOCK_DGRAM, 0);
        if (nmsg_sock < 0) {
                perror("socket");
                exit(1);
        }

        /* connect socket */
        if (connect(nmsg_sock, (struct sockaddr *) &nmsg_sockaddr,
                    sizeof(nmsg_sockaddr)) < 0)
        {
                perror("connect");
                exit(1);
        }

	/* create nmsg output */
	output = nmsg_output_open_sock(nmsg_sock, DST_MTU);
	if (output == NULL)
		fail("unable to nmsg_output_open_sock()");
	
	/* load modules */
	ms = nmsg_pbmodset_init(MODULE_DIR, 0);
	if (ms == NULL)
		fail("unable to nmsg_pbmodset_init()");

	/* open handle to the linkpair module */
	mod = nmsg_pbmodset_lookup(ms, NMSG_VENDOR_ISC_ID, MSGTYPE_LINKPAIR_ID);
	if (mod == NULL)
		fail("unable to acquire module handle");

	/* initialize module */
	res = nmsg_pbmod_init(mod, &clos);
	if (res != nmsg_res_success)
		exit(res);

	/* initialize a scratch message */
	lp = calloc(1, sizeof(*lp));
	assert(lp != NULL);

	/* create and send pbufs */
	for (i = 1; i < sizeof(headers) - 1; i++) {
		Nmsg__NmsgPayload *np;
		struct timespec ts;

		res = nmsg_pbmod_message_init(mod, lp);
		assert(res == nmsg_res_success);

		lp->type = NMSG__ISC__LINKTYPE__redirect;
		nmsg_payload_put_str(&lp->src, NULL, http);
		nmsg_payload_put_str(&lp->dst, NULL, https);
		nmsg_payload_put_str(&lp->headers, &lp->has_headers, headers);

		nmsg_timespec_get(&ts);
		np = nmsg_payload_from_message(lp, NMSG_VENDOR_ISC_ID,
					       MSGTYPE_LINKPAIR_ID, &ts);
		assert(np != NULL);
		nmsg_pbmod_message_reset(mod, lp);
		nmsg_output_write(output, np);
	}

	/* finalize module */
	nmsg_pbmod_fini(mod, &clos);

	/* close nmsg output */
	nmsg_output_close(&output);

	/* unload modules */
	nmsg_pbmodset_destroy(&ms);

	/* cleanup */
	free(lp);

	return (res);
}

void fail(const char *str) {
	fprintf(stderr, "%s\n", str);
	exit(1);
}
