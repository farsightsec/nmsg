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

#include <time.h>

#include <nmsg.h>

/***
 *** Functions
 ***/

Nmsg__NmsgPayload *nmsg_payload_dup(const Nmsg__NmsgPayload *np);
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
nmsg_payload_free(Nmsg__NmsgPayload **np);
/*%<
 * Free an nmsg payload allocated by nmsg_payload_dup().
 *
 * \li	'*np' is a valid nmsg payload.
 *
 * Ensures:
 *
 * \li	*np is NULLed and memory used by the nmsg payload and its
 *	serialized data are freed.
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

Nmsg__NmsgPayload *
nmsg_payload_make(uint8_t *pbuf, size_t sz, unsigned vid, unsigned msgtype,
		  const struct timespec *ts);
/*%<
 * Create an nmsg payload.
 *
 * Requires:
 *
 * \li	'pbuf' is serialized data.
 *
 * \li	'sz' is the length of the serialized data.
 *
 * \li	'vid' is the vendor ID of the module which generated the serialized
 *	data.
 *
 * \li	'msgtype' is the message type of the module which generated the
 *	serialized data.
 *
 * \li	'ts' is the timestamp to embed in the nmsg payload.
 *
 * Returns:
 *
 * \li	An nmsg payload.
 */


Nmsg__NmsgPayload *
nmsg_payload_from_message(void *m, unsigned vid, unsigned msgtype,
			  const struct timespec *ts);
/*%<
 * Create an nmsg payload from a protobuf message.
 *
 * Requires:
 *
 * \li	'm' is an initialized protobuf message ready to be serialized.
 *
 * \li	'vid' is a vendor ID.
 *
 * \li	'msgtype' is a message type.
 *
 * \li	'ts' is the timestamp to embed in the nmsg payload.
 *
 * Returns:
 * \li	An nmsg payload.
 */

nmsg_res
nmsg_payload_put_ipstr(ProtobufCBinaryData *bdata, int *has, int af,
		       const char *src);
/*%<
 * Load a byte array payload field with an IP address converted from
 * presentation format.
 *
 * \li	'has' is the protobuf quantifier field. In protobuf struct
 *	definitions, a field prefixed with has_ or n_ accompanies optional
 *	or repeated fields.
 *
 * \li	'bdata' is the protobuf byte array field where the IP address
 *	should be stored.
 *
 * \li	'af' is an address family, AF_INET or AF_INET6.
 *
 * \li	'src' is the presentation form of an IP address.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_memfail
 * \li	nmsg_res_failure
 */

nmsg_res
nmsg_payload_put_str(ProtobufCBinaryData *bdata, int *has, const char *str);
/*%<
 * Load a byte array payload field with a string. The string is copied with
 * strdup().
 *
 * \li	'has' is the protobuf quantifier field. In protobuf struct
 *	definitions, a field prefixed with has_ or n_ accompanies optional
 *	or repeated fields.
 *
 * \li	'bdata' is the protobuf byte array field where the IP address
 *	should be stored.
 *
 * \li	'str' is the \0 terminated string to copy.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_memfail
 */

#endif /* NMSG_PAYLOAD_H */
