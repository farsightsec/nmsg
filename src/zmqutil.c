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

#include <stdint.h>

#include "nmsgtool.h"

static void *
zmqutil_setsockopts(void *s, int socket_type) {
	static const uint64_t u64_thousand = 1000;
	static const int i_thousand = 1000;

	if (socket_type == ZMQ_SUB) {
		if (zmq_setsockopt(s, ZMQ_SUBSCRIBE, "NMSG", 4)) {
			perror("zmq_setsockopt");
			return (NULL);
		}
	} else if (socket_type == ZMQ_PUB) {
		if (zmq_setsockopt(s, ZMQ_HWM, &u64_thousand, sizeof(u64_thousand))) {
			perror("zmq_setsockopt");
			return (NULL);
		}
		if (zmq_setsockopt(s, ZMQ_LINGER, &i_thousand, sizeof(i_thousand))) {
			perror("zmq_setsockopt");
			return (NULL);
		}
	}

	return (s);
}

void *
zmqutil_create_accept_socket(void *ctx, int socket_type, const char *endpoint) {
	void *s;

	s = zmq_socket(ctx, socket_type);
	if (s == NULL) {
		perror("zmq_socket");
		return (NULL);
	}

	if (!zmqutil_setsockopts(s, socket_type)) {
		zmq_close(s);
		return (NULL);
	}

	if (zmq_bind(s, endpoint)) {
		perror("zmq_bind");
		zmq_close(s);
		return (NULL);
	}

	return (s);
}

void *
zmqutil_create_connect_socket(void *ctx, int socket_type, const char *endpoint) {
	void *s;

	s = zmq_socket(ctx, socket_type);
	if (s == NULL) {
		perror("zmq_socket");
		return (NULL);
	}

	if (!zmqutil_setsockopts(s, socket_type)) {
		zmq_close(s);
		return (NULL);
	}

	if (zmq_connect(s, endpoint)) {
		perror("zmq_connect");
		zmq_close(s);
		return (NULL);
	}

	return (s);
}
