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

/*! \file nmsg/payload.h
 * \brief Utility functions for manipulating nmsg payloads.
 */

#include <time.h>

#include <nmsg.h>

/**
 * Duplicate an nmsg payload.
 *
 * \param[in] np nmsg payload
 *
 * \return Copy of the payload which must be freed by the caller using
 *	nmsg_payload_free().
 */
Nmsg__NmsgPayload *nmsg_payload_dup(const Nmsg__NmsgPayload *np);

/**
 * Free an nmsg payload.
 *
 * \param[in] np pointer to an nmsg payload
 */
void
nmsg_payload_free(Nmsg__NmsgPayload **np);

/**
 * Determine the serialized length of an nmsg payload.
 *
 * \param[in] np nmsg payload
 *
 * \return Length in octets the payload will consume after serialization.
 */
size_t
nmsg_payload_size(const Nmsg__NmsgPayload *np);

/**
 * Create an nmsg payload.
 *
 * \param[in] pbuf serialized data.
 *
 * \param[in] sz length of the serialized data.
 *
 * \param[in] vid vendor ID of the module which generated the serialized data.
 *
 * \param[in] msgtype message type of the module which generated the serialized
 *	data.
 *
 * \param[in] ts timestamp to embed in the nmsg payload.
 *
 * \return nmsg payload.
 */
Nmsg__NmsgPayload *
nmsg_payload_make(uint8_t *pbuf, size_t sz, unsigned vid, unsigned msgtype,
		  const struct timespec *ts);

/**
 * Create an nmsg payload from a protobuf message.
 *
 * \param[in] m initialized protobuf message ready to be serialized.
 *
 * \param[in] vid vendor ID.
 *
 * \param[in] msgtype message type.
 *
 * \param[in] ts timestamp to embed in the nmsg payload.
 *
 * \return nmsg payload.
 */
Nmsg__NmsgPayload *
nmsg_payload_from_message(void *m, unsigned vid, unsigned msgtype,
			  const struct timespec *ts);

/**
 * Load a byte array nmsg payload field with an IP address converted from
 * presentation format.
 *
 * \param[in] has protobuf quantifier field. In protobuf struct definitions, a
 *	field prefixed with has_ or n_ accompanies optional or repeated fields.
 *	May be NULL if the field is required.
 *
 * \param[out] bdata protobuf byte array field where the IP address should be
 *	stored.
 *
 * \param[in] af address family, AF_INET or AF_INET6.
 *
 * \param[in] src presentation form of an IP address.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_payload_put_ipstr(ProtobufCBinaryData *bdata, int *has, int af,
		       const char *src);

/**
 * Load a byte array nmsg payload field with a string. The string is copied with
 * strdup().
 *
 * \param[in] has protobuf quantifier field. In protobuf struct definitions, a
 *	field prefixed with has_ or n_ accompanies optional or repeated fields.
 *	May be NULL if the field is required.
 *
 * \param[out] bdata is the protobuf byte array field where the string should be
 *	stored.
 *
 * \param[in] str \\0 terminated string to copy.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 */
nmsg_res
nmsg_payload_put_str(ProtobufCBinaryData *bdata, int *has, const char *str);

#endif /* NMSG_PAYLOAD_H */
