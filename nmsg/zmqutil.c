/*
 * Copyright (c) 2012 by Internet Systems Consortium, Inc. ("ISC")
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

#include "private.h"

/* Export. */

void *
nmsg_zmqutil_init(int io_threads) {
	return (zmq_init(io_threads));
}

int
nmsg_zmqutil_term(void *ctx) {
	return (zmq_term(ctx));
}

void *
nmsg_zmqutil_create_accept_socket(void *ctx, int socket_type, const char *endpoint) {
	void *s;

	s = zmq_socket(ctx, socket_type);
	if (s == NULL)
		return (NULL);

	if (zmq_bind(s, endpoint))
		return (NULL);

	if (socket_type == ZMQ_SUB) {
		if (zmq_setsockopt(s, ZMQ_SUBSCRIBE, "NMSG", 4))
			return (NULL);
	}

	return (s);
}

void *
nmsg_zmqutil_create_connect_socket(void *ctx, int socket_type, const char *endpoint) {
	void *s;

	s = zmq_socket(ctx, socket_type);
	if (s == NULL)
		return (NULL);

	if (zmq_connect(s, endpoint))
		return (NULL);

	return (s);
}
