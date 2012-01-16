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

#ifndef NMSG_ZMQUTIL_H
#define NMSG_ZMQUTIL_H

/*! \file nmsg/zmqutil.h
 * \brief libzmq utility functions.
 */

/**
 * Wrapper function for zmq_init().
 *
 * \return ZMQ context.
 */
void *
nmsg_zmqutil_init(int io_threads);

/**
 * Wrapper function for zmq_term().
 */
int
nmsg_zmqutil_term(void *ctx);

/**
 * Create a ZMQ socket for accepting connections at the specified endpoint.
 *
 * \param[in] ctx ZMQ context.
 * \param[in] socket_type ZMQ socket type, e.g. ZMQ_PUB, ZMQ_SUB.
 * \param[in] endpoint ZMQ endpoint string.
 */
void *
nmsg_zmqutil_create_accept_socket(void *ctx, int socket_type, const char *endpoint);

/**
 * Create a ZMQ socket and connect it to the specified endpoint.
 *
 * \param[in] ctx ZMQ context.
 * \param[in] socket_type ZMQ socket type, e.g. ZMQ_PUB, ZMQ_SUB.
 * \param[in] endpoint ZMQ endpoint string.
 */
void *
nmsg_zmqutil_create_connect_socket(void *ctx, int socket_type, const char *endpoint);

#endif /* NMSG_ZMQUTIL_H */
