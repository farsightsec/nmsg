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
#define DST_MTU		1280

#define nmsf(a,b,c,d,e) do { \
	nmsg_res _res; \
	_res = nmsg_message_set_field(a,b,c,(uint8_t *) d,e); \
	assert(_res == nmsg_res_success); \
} while (0)

/* Functions. */

static void
fail(const char *str) {
	fprintf(stderr, "%s\n", str);
	exit(1);
}

int
main(void) {
	int nmsg_sock;
	nmsg_message_t msg;
	nmsg_msgmod_t mod;
	nmsg_output_t output;
	nmsg_res res;
	struct sockaddr_in nmsg_sockaddr;
	void *clos;

	/* initialize libnmsg */
	res = nmsg_init();
	if (res != nmsg_res_success)
		fail("unable to initialize libnmsg\n");

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

	/* open handle to the email module */
	mod = nmsg_msgmod_lookup(NMSG_VENDOR_ISC_ID, NMSG_VENDOR_ISC_EMAIL_ID);
	if (mod == NULL)
		fail("unable to acquire module handle");

	/* initialize module */
	res = nmsg_msgmod_init(mod, &clos);
	if (res != nmsg_res_success)
		exit(res);

	/* create and send pbuf */
	char srcip[] = "127.0.0.1";
	char srchost[] = "localhost.localdomain";
	char helo[] = "helo";
	char from[] = "foo@bar.example";
	char rcpt0[] = "bar@baz.example.com";
	char rcpt1[] = "baz@baz.example.com";
	uint32_t ip;
	unsigned type;

	msg = nmsg_message_init(mod);
	assert(msg != NULL);

	res = nmsg_message_enum_name_to_value(msg, "type", "spamtrap", &type);
	assert(res == nmsg_res_success);
	nmsf(msg, "type", 0, &type, sizeof(type));

	inet_pton(AF_INET, srcip, &ip);
	nmsf(msg, "srcip", 0, &ip, sizeof(ip));

	nmsf(msg, "srchost", 0, srchost, sizeof(srchost));

	nmsf(msg, "helo", 0, helo, sizeof(helo));
	nmsf(msg, "from", 0, from, sizeof(from));
	nmsf(msg, "rcpt", 0, rcpt0, sizeof(rcpt0));
	nmsf(msg, "rcpt", 1, rcpt1, sizeof(rcpt1));

	nmsg_output_write(output, msg);

	nmsg_message_destroy(&msg);

	/* finalize module */
	nmsg_msgmod_fini(mod, &clos);

	/* close nmsg output */
	nmsg_output_close(&output);

	return (res);
}
