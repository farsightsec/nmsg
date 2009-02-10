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
#include <nmsg/isc/http.pb-c.h>

/* Macros. */

#define DEBUG_LEVEL	0

#define MODULE_DIR	"/usr/local/lib/nmsg"
#define MODULE_VENDOR	"ISC"
#define MODULE_MSGTYPE	"http"

#define DST_ADDRESS	"127.0.0.1"
#define DST_PORT	8430
#define DST_MTU		1280

/* Forward. */

void fail(const char *str);

/* Functions. */

int main(void) {
	Nmsg__Isc__Http *http;
	Nmsg__NmsgPayload *np;
	int nmsg_sock;
	nmsg_buf buf;
	nmsg_pbmod mod;
	nmsg_pbmodset ms;
	nmsg_res res;
	struct sockaddr_in nmsg_sockaddr;
	struct timespec ts;
	unsigned vid, msgtype;
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

	/* create nmsg output buf */
	buf = nmsg_output_open_sock(nmsg_sock, DST_MTU);
	if (buf == NULL)
		fail("unable to nmsg_output_open_sock()");

	/* load modules */
	ms = nmsg_pbmodset_init(MODULE_DIR, 0);
	if (ms == NULL)
		fail("unable to nmsg_pbmodset_init()");

	/* open handle to the http module */
	vid = nmsg_pbmodset_vname_to_vid(ms, MODULE_VENDOR);
	msgtype = nmsg_pbmodset_mname_to_msgtype(ms, vid, MODULE_MSGTYPE);
	mod = nmsg_pbmodset_lookup(ms, vid, msgtype);
	if (mod == NULL)
		fail("unable to acquire module handle");

	/* initialize module */
	res = nmsg_pbmod_init(mod, &clos, DEBUG_LEVEL);
	if (res != nmsg_res_success)
		exit(res);

	/* create and send pbuf */

	uint16_t srcport = 49152;
	uint16_t dstport = 8080;
	char request[] = "GET / HTTP/1.0\n";
	char srcip[] = "127.0.0.1";
	char dstip[] = "192.0.2.1";

	http = calloc(1, sizeof(*http));
	assert(http != NULL);

	http->base.descriptor = mod->pbdescr;
	http->type = NMSG__ISC__HTTP_TYPE__sinkhole;
	nmsg_payload_put_ipstr(&http->srcip, &http->has_srcip, AF_INET, srcip);
	nmsg_payload_put_ipstr(&http->dstip, &http->has_dstip, AF_INET, dstip);
	nmsg_payload_put_str(&http->srchost, &http->has_srchost,
			     "localhost.localdomain");
	http->srcport = srcport;
	http->has_srcport = 1;
	http->dstport = dstport;
	http->has_dstport = 1;
	nmsg_payload_put_str(&http->request, &http->has_request, request);

	nmsg_time_get(&ts);
	np = nmsg_payload_from_message((ProtobufCMessage *) http, vid, msgtype,
				       &ts);
	free(http->srchost.data);
	free(http->request.data);
	free(http->srcip.data);
	free(http->dstip.data);
	assert(np != NULL);
	free(http);
	nmsg_output_append(buf, np);

	/* finalize module */
	nmsg_pbmod_fini(mod, &clos);

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
