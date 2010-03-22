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
#include <nmsg/isc/defs.h>

/* Macros. */

#define DST_ADDRESS	"127.0.0.1"
#define DST_PORT	8430
#define DST_BUFSZ	1280

/* Data structures. */

struct ctx_nmsg {
	nmsg_output_t output;
	nmsg_msgmod_t mod;
	void *clos_mod;
};

/* Functions. */

static void
setup_nmsg(struct ctx_nmsg *ctx, const char *ip, uint16_t port, size_t bufsz,
	   unsigned vid, unsigned msgtype)
{
	struct sockaddr_in nmsg_sockaddr;
	nmsg_res res;
	int nmsg_sock;

	/* initialize libnmsg */
	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "unable to initialize libnmsg\n");
		exit(1);
	}

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

	/* open handle to the http module */
	ctx->mod = nmsg_msgmod_lookup(vid, msgtype);
	if (ctx->mod == NULL) {
		fprintf(stderr, "nmsg_msgmod_lookup() failed\n");
		exit(1);
	}

	/* initialize module */
	res = nmsg_msgmod_init(ctx->mod, &ctx->clos_mod);
	if (res != nmsg_res_success)
		exit(res);
}

static void
shutdown_nmsg(struct ctx_nmsg *ctx) {
	/* finalize module */
	nmsg_msgmod_fini(ctx->mod, &ctx->clos_mod);

	/* close nmsg output */
	nmsg_output_close(&ctx->output);
}

#define nmsf(a,b,c,d,e) do { \
	nmsg_res _res; \
	_res = nmsg_message_set_field(a,b,c,d,e); \
	assert(_res == nmsg_res_success); \
} while (0)

/* send an ipconn payload
 *	srcip, dstip are network byte order
 *	srcport, dstport are host byte order
 */
static void
send_nmsg_ipconn_payload(struct ctx_nmsg *ctx, uint32_t *proto,
			 uint32_t *srcip, uint32_t *dstip,
			 uint32_t *srcport, uint32_t *dstport)
{
	nmsg_message_t msg;

	msg = nmsg_message_init(ctx->mod);
	assert(msg != NULL);

	nmsg_message_set_time(msg, NULL);

	if (proto != NULL)
		nmsf(msg, "proto", 0, (uint8_t *) proto, sizeof(*proto));

	if (srcip != NULL)
		nmsf(msg, "srcip", 0, (uint8_t *) srcip, sizeof(*srcip));

	if (dstip != NULL)
		nmsf(msg, "dstip", 0, (uint8_t *) dstip, sizeof(*dstip));

	if (srcport != NULL)
		nmsf(msg, "srcport", 0, (uint8_t *) srcport, sizeof(*srcport));

	if (dstport != NULL)
		nmsf(msg, "dstport", 0, (uint8_t *) dstport, sizeof(*dstport));

	nmsg_output_write(ctx->output, msg);
	nmsg_message_destroy(&msg);
}

int main(int argc, char **argv) {
	struct ctx_nmsg ctx;
	int i;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <number of payloads>\n", argv[0]);
		return (1);
	}

	setup_nmsg(&ctx, DST_ADDRESS, DST_PORT, DST_BUFSZ,
		   NMSG_VENDOR_ISC_ID, NMSG_VENDOR_ISC_IPCONN_ID);

	/* send test payloads */
	for (i = 0; i < atoi(argv[1]); i++) {
		/* arbitrary values */
		uint32_t proto = IPPROTO_TCP;
		uint32_t srcport = i + 42;
		uint32_t dstport = i + 43;
		uint32_t srcip = htonl(i + 0x0A000000); /* 10.0.0.0 */
		uint32_t dstip = htonl(i + 0xC0A80000); /* 192.168.0.0 */

		send_nmsg_ipconn_payload(&ctx, &proto, &srcip, &dstip,
					 &srcport, &dstport);
	}

	shutdown_nmsg(&ctx);

	return (0);
}
