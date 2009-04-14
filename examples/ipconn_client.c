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
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/isc/nmsgpb_isc_ipconn.h>

/* Macros. */

#define MODULE_DIR	"/usr/local/lib/nmsg"

#define DST_ADDRESS	"127.0.0.1"
#define DST_PORT	8430
#define DST_BUFSZ	1280

/* Data structures. */

struct ctx_nmsg {
	nmsg_output_t output;
	nmsg_pbmod_t mod;
	nmsg_pbmodset_t ms;
	void *clos_mod;
};

/* Forward. */

static void
setup_nmsg(struct ctx_nmsg *ctx, const char *ip, uint16_t port, size_t bufsz,
	   const char *module_dir, unsigned vid, unsigned msgtype);

static void
shutdown_nmsg(struct ctx_nmsg *ctx);

static void
send_nmsg_ipconn_payload(struct ctx_nmsg *ctx, uint16_t *proto,
			 uint32_t *srcip, uint32_t *dstip,
			 uint16_t *srcport, uint16_t *dstport);

/* Functions. */

static void
setup_nmsg(struct ctx_nmsg *ctx, const char *ip, uint16_t port, size_t bufsz,
	   const char *module_dir, unsigned vid, unsigned msgtype)
{
	struct sockaddr_in nmsg_sockaddr;
	nmsg_res res;
	int nmsg_sock;

	/* set dst address / port */
	if (inet_pton(AF_INET, ip, &nmsg_sockaddr.sin_addr)) {
		nmsg_sockaddr.sin_family = AF_INET;
		nmsg_sockaddr.sin_port = htons(port);
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
	ctx->output = nmsg_output_open_sock(nmsg_sock, bufsz);
	if (ctx->output == NULL) {
		fprintf(stderr, "nmsg_output_open_sock() failed\n");
		exit(1);
	}
	nmsg_output_set_buffered(ctx->output, false);

	/* load modules */
	ctx->ms = nmsg_pbmodset_init(module_dir, 0);
	if (ctx->ms == NULL) {
		fprintf(stderr, "nmsg_pbmodset_init() failed\n");
		exit(1);
	}

	/* open handle to the http module */
	ctx->mod = nmsg_pbmodset_lookup(ctx->ms, vid, msgtype);
	if (ctx->mod == NULL) {
		fprintf(stderr, "nmsg_pbmodset_lookup() failed\n");
		exit(1);
	}

	/* initialize module */
	res = nmsg_pbmod_init(ctx->mod, &ctx->clos_mod);
	if (res != nmsg_res_success)
		exit(res);
}

static void
shutdown_nmsg(struct ctx_nmsg *ctx) {
	/* finalize module */
	nmsg_pbmod_fini(ctx->mod, &ctx->clos_mod);

	/* close nmsg output */
	nmsg_output_close(&ctx->output);

	/* unload modules */
	nmsg_pbmodset_destroy(&ctx->ms);
}

/* send an ipconn payload
 *	srcip, dstip are network byte order
 *	srcport, dstport are host byte order
 */
static void
send_nmsg_ipconn_payload(struct ctx_nmsg *ctx, uint16_t *proto,
			 uint32_t *srcip, uint32_t *dstip,
			 uint16_t *srcport, uint16_t *dstport)
{
	Nmsg__Isc__IPConn ipconn;
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	struct timespec ts;

	memset(&ipconn, 0, sizeof(ipconn));
	res = nmsg_pbmod_message_init(ctx->mod, &ipconn);
	assert(res == nmsg_res_success);

	if (proto != NULL) {
		ipconn.proto = *proto;
		ipconn.has_proto = true;
	}

	if (srcip != NULL) {
		ipconn.srcip.data = (uint8_t *) srcip;
		ipconn.srcip.len = 4;
		ipconn.has_srcip = true;
	}

	if (dstip != NULL) {
		ipconn.dstip.data = (uint8_t *) dstip;
		ipconn.dstip.len = 4;
		ipconn.has_dstip = true;
	}

	if (srcport != NULL) {
		ipconn.srcport = *srcport;
		ipconn.has_srcport = true;
	}

	if (dstport != NULL) {
		ipconn.dstport = *dstport;
		ipconn.has_dstport = true;
	}

	nmsg_timespec_get(&ts);

	np = nmsg_payload_from_message(&ipconn, NMSG_VENDOR_ISC_ID,
				       MSGTYPE_IPCONN_ID, &ts);
	if (np != NULL)
		nmsg_output_write(ctx->output, np);
}


int main(int argc, char **argv) {
	struct ctx_nmsg ctx;
	int i;


	if (argc != 2) {
		fprintf(stderr, "usage: %s <number of payloads>\n", argv[0]);
		return (1);
	}

	setup_nmsg(&ctx, DST_ADDRESS, DST_PORT, DST_BUFSZ, MODULE_DIR,
		   NMSG_VENDOR_ISC_ID, MSGTYPE_IPCONN_ID);

	/* send test payloads */
	for (i = 0; i < atoi(argv[1]); i++) {
		/* arbitrary values */
		uint16_t proto = IPPROTO_TCP;
		uint16_t srcport = i + 42;
		uint16_t dstport = i + 43;
		uint32_t srcip = htonl(i + 0x0A000000); /* 10.0.0.0 */
		uint32_t dstip = htonl(i + 0xC0A80000); /* 192.168.0.0 */

		send_nmsg_ipconn_payload(&ctx, &proto, &srcip, &dstip,
					 &srcport, &dstport);
	}

	shutdown_nmsg(&ctx);

	return (0);
}
