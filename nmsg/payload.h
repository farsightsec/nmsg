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

#ifndef NMSG_PAYLOAD_H
#define NMSG_PAYLOAD_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/payload.h
 * \brief Utility functions for manipulating nmsg payloads.
 */

/***
 *** Imports
 ***/

#include <nmsg.h>

/***
 *** Functions
 ***/

Nmsg__NmsgPayload *nmsg_payload_dup(const Nmsg__NmsgPayload *np,
				    ProtobufCAllocator *ca);
/*%<
 * Duplicate an nmsg payload.
 *
 * Requires:
 *
 * \li	'np' is a valid nmsg payload.
 *
 * \li	'ca' is an allocator object in which the 'alloc' field must be set,
 *	and the 'allocator_data' field may optionally be set.
 *
 * Returns:
 *
 * \li	A copy of the 'np' argument which must be freed by the caller.
 */

void
nmsg_payload_free(Nmsg__NmsgPayload **np, ProtobufCAllocator *ca);
/*%<
 * Free an nmsg payload allocated by nmsg_payload_dup().
 *
 * \li	'*np' is a valid nmsg payload.
 *
 * \li	'ca' is an allocator object in which the 'free' field must be set,
 *	and the 'allocator_data' field may optionally be set.
 *
 * Ensures:
 *
 * \li	*np is NULLed and resources allocated by nmsg_payload_dup() are
 * freed.
 */

size_t
nmsg_payload_size(const Nmsg__NmsgPayload *np);
/*%<
 * Determine the length of a serialized nmsg payload.
 *
 * Requires:
 *
 * \li	'np' is a valid nmsg payload.
 *
 * Returns:
 *
 * \li	Length (in octets) the payload will consume after serialization.
 */

#endif /* NMSG_PAYLOAD_H */
