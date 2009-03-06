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

/* Import. */

#include "nmsg_port.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "nmsg.h"
#include "payload.h"

/* Export. */

Nmsg__NmsgPayload *
nmsg_payload_dup(const Nmsg__NmsgPayload *np) {
	Nmsg__NmsgPayload *dup;

	dup = malloc(sizeof(*dup));
	if (dup == NULL)
		return (NULL);
	memcpy(dup, np, sizeof(*dup));
	if (np->has_payload && dup->payload.data != NULL) {
		dup->payload.data = malloc(np->payload.len);
		if (dup->payload.data == NULL) {
			free(dup);
			return (NULL);
		}
		memcpy(dup->payload.data, np->payload.data, np->payload.len);
	}
	if (np->n_user > 0) {
		dup->user = malloc(np->n_user * sizeof(*(np->user)));
		if (dup->user == NULL) {
			if (dup->payload.data != NULL)
				free(dup->payload.data);
			free(dup);
			return (NULL);
		}
		memcpy(dup->user, np->user, np->n_user * sizeof(*(np->user)));
	}
	return (dup);
}

void
nmsg_payload_free(Nmsg__NmsgPayload **np) {
	if ((*np)->has_payload && (*np)->payload.data != NULL)
		free((*np)->payload.data);
	if ((*np)->n_user > 0)
		free((*np)->user);
	free(*np);
	*np = NULL;
}

size_t
nmsg_payload_size(const Nmsg__NmsgPayload *np) {
	size_t sz;
	Nmsg__NmsgPayload copy;

	copy = *np;
	copy.payload.len = 0;
	copy.payload.data = NULL;
	sz = nmsg__nmsg_payload__get_packed_size(&copy);

	sz += np->payload.len;

	/* varint encoded length */
	if (np->payload.len >= (1 << 7))
		sz += 1;
	if (np->payload.len >= (1 << 14))
		sz += 1;

	return (sz);
}

Nmsg__NmsgPayload *
nmsg_payload_make(uint8_t *pbuf, size_t sz, unsigned vid, unsigned msgtype,
		  const struct timespec *ts)
{
	Nmsg__NmsgPayload *np;

	np = calloc(1, sizeof(*np));
	if (np == NULL)
		return (NULL);
	nmsg__nmsg_payload__init(np);
	np->base.n_unknown_fields = 0;
	np->base.unknown_fields = NULL;
	np->vid = vid;
	np->msgtype = msgtype;
	np->time_sec = ts->tv_sec;
	np->time_nsec = ts->tv_nsec;
	np->has_payload = true;
	np->payload.data = pbuf;
	np->payload.len = sz;

	return (np);
}

Nmsg__NmsgPayload *
nmsg_payload_from_message(void *m, unsigned vid, unsigned msgtype,
			  const struct timespec *ts)
{
	ProtobufCBufferSimple sbuf;
	size_t sz;

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.data = malloc(1024);
	sbuf.must_free_data = 1;
	if (sbuf.data == NULL)
		return (NULL);
	sbuf.alloced = 1024;

	sz = protobuf_c_message_pack_to_buffer((ProtobufCMessage *) m,
					       (ProtobufCBuffer *) &sbuf);
	return (nmsg_payload_make(sbuf.data, sz, vid, msgtype, ts));
}

nmsg_res
nmsg_payload_put_ipstr(ProtobufCBinaryData *bdata, int *has, int af,
		       const char *src)
{
	char ip[INET6_ADDRSTRLEN];

	if (af != AF_INET && af != AF_INET6)
		return (nmsg_res_failure);

	if (inet_pton(af, src, ip) != 1)
		return (nmsg_res_failure);

	if (af == AF_INET) {
		bdata->data = malloc(4);
		if (bdata->data == NULL)
			return (nmsg_res_memfail);
		memcpy(bdata->data, ip, 4);
		bdata->len = 4;
	} else if (af == AF_INET6) {
		bdata->data = malloc(16);
		if (bdata->data == NULL)
			return (nmsg_res_memfail);
		memcpy(bdata->data, ip, 16);
		bdata->len = 16;
	}

	if (has != NULL)
		*has += 1;

	return (nmsg_res_success);
}

nmsg_res
nmsg_payload_put_str(ProtobufCBinaryData *bdata, int *has, const char *str) {
	bdata->data = NULL;
	bdata->data = (uint8_t *) strdup(str);
	if (bdata->data == NULL)
		return (nmsg_res_memfail);
	bdata->len = strlen(str) + 1; /* \0 terminated */

	if (has != NULL)
		*has += 1;

	return (nmsg_res_success);
}
