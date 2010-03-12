/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nmsg.h"
#include "private.h"

#include "transparent.h"

/* Export. */

struct nmsg_message *
nmsg_message_init(struct nmsg_msgmod *mod) {
	struct nmsg_message *msg;
	nmsg_res res;

	/* allocate space */
	msg = calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	/* initialize ->mod */
	msg->mod = mod;

	/* initialize ->message */
	res = _nmsg_message_init_message(msg);
	if (res != nmsg_res_success) {
		free(msg);
		return (NULL);
	}

	/* initialize ->np */
	res = _nmsg_message_init_payload(msg);
	if (res != nmsg_res_success) {
		free(msg->message);
		free(msg);
		return (NULL);
	}

	return (msg);
}

struct nmsg_message *
_nmsg_message_dup(struct nmsg_message *msg) {
	struct nmsg_message *msgdup;

	/* allocate space */
	msgdup = calloc(1, sizeof(*msgdup));
	if (msgdup == NULL)
		return (NULL);

	/* initialize ->mod */
	msgdup->mod = msg->mod;

	/* initialize ->message */
	if (msg->message != NULL &&
	    msg->mod->plugin->type == nmsg_msgmod_type_transparent &&
	    msg->mod->plugin->pbdescr != NULL)
	{
		size_t msgsz = msg->mod->plugin->pbdescr->sizeof_message;

		msgdup->message = malloc(msgsz);
		if (msgdup->message == NULL) {
			free(msgdup);
			return (NULL);
		}

		/* XXX fix this */
		/* memcpy of a ProtobufCMessage only performs a shallow copy; */
		/* this means that an nmsg_message_dup'd message can't be */
		/* validly free'd. */
		memcpy(msgdup->message, msg->message, msgsz);
		/* XXX */
	}

	/* initialize ->np */
	if (msg->np != NULL) {
		msgdup->np = malloc(sizeof(*msg->np));
		if (msgdup->np == NULL) {
			free(msgdup->message);
			free(msgdup);
			return (NULL);
		}
		memcpy(msgdup->np, msg->np, sizeof(*msg->np));

		if (msg->np->has_payload && msg->np->payload.data != NULL) {
			msgdup->np->payload.data = malloc(msg->np->payload.len);
			if (msgdup->np->payload.data == NULL) {
				free(msgdup->np);
				free(msgdup->message);
				free(msgdup);
				return (NULL);
			}
			memcpy(msgdup->np->payload.data, msg->np->payload.data,
			       msg->np->payload.len);
		}
	}

	return (msgdup);
}

struct nmsg_message *
_nmsg_message_from_payload(Nmsg__NmsgPayload *np) {
	struct nmsg_message *msg;

	/* allocate space */
	msg = calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	/* initialize ->mod */
	msg->mod = nmsg_msgmod_lookup(np->vid, np->msgtype);

	/* initialize ->message */
	msg->message = NULL;

	/* initialize ->np */
	msg->np = np;

	/* initialize ->msg_clos */
	if (msg->mod->plugin->msg_load)
		msg->mod->plugin->msg_load(msg, &msg->msg_clos);

	return (msg);
}

struct nmsg_message *
nmsg_message_from_raw_payload(nmsg_msgmod_t mod, uint8_t *data, size_t sz,
			      const struct timespec *ts)
{
	nmsg_message_t msg;
	Nmsg__NmsgPayload *np;

	np = calloc(1, sizeof(*np));
	if (np == NULL)
		return (NULL);
	nmsg__nmsg_payload__init(np);
	np->base.n_unknown_fields = 0;
	np->base.unknown_fields = NULL;
	np->vid = mod->plugin->vendor.id;
	np->msgtype = mod->plugin->msgtype.id;
	np->time_sec = ts->tv_sec;
	np->time_nsec = ts->tv_nsec;
	np->has_payload = true;
	np->payload.data = data;
	np->payload.len = sz;

	msg = _nmsg_message_from_payload(np);
	if (msg == NULL) {
		free(np);
		return (NULL);
	}
	return (msg);
}

nmsg_res
_nmsg_message_init_message(struct nmsg_message *msg) {
	if (msg->mod->plugin->type == nmsg_msgmod_type_transparent &&
	    msg->mod->plugin->pbdescr != NULL)
	{
		msg->message = calloc(1, msg->mod->plugin->pbdescr->sizeof_message);
		if (msg->message == NULL)
			return (nmsg_res_memfail);
		msg->message->descriptor = msg->mod->plugin->pbdescr;
	} else {
		msg->message = NULL;
	}
	return (nmsg_res_success);
}

nmsg_res
_nmsg_message_init_payload(struct nmsg_message *msg) {
	struct timespec ts;

	msg->np = malloc(sizeof(*msg->np));
	if (msg->np == NULL)
		return (nmsg_res_memfail);
	nmsg__nmsg_payload__init(msg->np);
	msg->np->vid = msg->mod->plugin->vendor.id;
	msg->np->msgtype = msg->mod->plugin->msgtype.id;
	nmsg_timespec_get(&ts);
	msg->np->time_sec = ts.tv_sec;
	msg->np->time_nsec = ts.tv_nsec;

	return (nmsg_res_success);
}

void
nmsg_message_destroy(struct nmsg_message **msg) {
	if ((*msg)->mod->plugin->msg_fini != NULL)
		(*msg)->mod->plugin->msg_fini(*msg, (*msg)->msg_clos);

	if ((*msg)->message != NULL) {
		protobuf_c_message_free_unpacked((*msg)->message, NULL);
		(*msg)->message = NULL;
	}
	if ((*msg)->np != NULL)
		_nmsg_payload_free(&(*msg)->np);

	free(*msg);
	*msg = NULL;
}

nmsg_message_t
nmsg_message_unpack(struct nmsg_msgmod *mod, uint8_t *data, size_t len) {
	struct nmsg_message *msg;

	if (mod->plugin->type != nmsg_msgmod_type_transparent || mod->plugin->pbdescr == NULL)
		return (NULL);

	msg = calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	msg->mod = mod;

	msg->message = protobuf_c_message_unpack(mod->plugin->pbdescr, NULL, len, data);
	if (msg->message == NULL) {
		free(msg);
		return (NULL);
	}

	return (msg);
}

nmsg_res
_nmsg_message_deserialize(struct nmsg_message *msg) {
	if (msg->message != NULL)
		return (nmsg_res_success);

	if (msg->np != NULL) {
		if (msg->np->has_payload == 0)
			return (nmsg_res_failure);
		msg->message = protobuf_c_message_unpack(msg->mod->plugin->pbdescr, NULL,
							 msg->np->payload.len,
							 msg->np->payload.data);
		if (msg->message == NULL)
			return (nmsg_res_memfail);
		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

nmsg_res
_nmsg_message_serialize(struct nmsg_message *msg) {
	ProtobufCBufferSimple sbuf;
	nmsg_res res;
	size_t sz;

	if (msg->message != NULL) {
		if (msg->np == NULL) {
			res = _nmsg_message_init_payload(msg);
			if (res != nmsg_res_success)
				return (res);
		}

		sbuf.base.append = protobuf_c_buffer_simple_append;
		sbuf.len = 0;
		sbuf.data = malloc(1024);
		if (sbuf.data == NULL)
			return (nmsg_res_memfail);
		sbuf.must_free_data = 1;
		sbuf.alloced = 1024;

		sz = protobuf_c_message_pack_to_buffer((ProtobufCMessage *) msg->message,
						       (ProtobufCBuffer *) &sbuf);
		if (msg->np->payload.data != NULL)
			free(msg->np->payload.data);

		msg->np->has_payload = true;
		msg->np->payload.data = sbuf.data;
		msg->np->payload.len = sz;
	}

	return (nmsg_res_success);
}

nmsg_res
nmsg_message_to_pres(struct nmsg_message *msg, char **pres, const char *endline) {
	if (msg->mod == NULL)
		return (nmsg_res_failure);
	switch (msg->mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_message_payload_to_pres(msg, pres, endline));
	case nmsg_msgmod_type_opaque:
		if (msg->mod->plugin->payload_to_pres != NULL)
			return (msg->mod->plugin->payload_to_pres(msg->np, pres, endline));
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_msgmod_t
nmsg_message_get_msgmod(nmsg_message_t msg) {
	return (msg->mod);
}

int32_t
nmsg_message_get_vid(nmsg_message_t msg) {
	return (msg->np->vid);
}

int32_t
nmsg_message_get_msgtype(nmsg_message_t msg) {
	return (msg->np->msgtype);
}

const void *
nmsg_message_get_payload(nmsg_message_t msg) {
	_nmsg_message_deserialize(msg);
	return ((const void *) msg->message);
}

void
nmsg_message_get_time(nmsg_message_t msg, struct timespec *ts) {
	ts->tv_sec = msg->np->time_sec;
	ts->tv_nsec = msg->np->time_nsec;
}

void
nmsg_message_set_time(nmsg_message_t msg, struct timespec *ts) {
	msg->np->time_sec = ts->tv_sec;
	msg->np->time_nsec = ts->tv_nsec;
}

uint32_t
nmsg_message_get_source(nmsg_message_t msg) {
	if (msg->np->has_source)
		return (msg->np->source);
	return (0);
}

uint32_t
nmsg_message_get_operator(nmsg_message_t msg) {
	if (msg->np->has_operator_)
		return (msg->np->operator_);
	return (0);
}

uint32_t
nmsg_message_get_group(nmsg_message_t msg) {
	if (msg->np->has_group)
		return (msg->np->group);
	return (0);
}

void
nmsg_message_set_source(nmsg_message_t msg, uint32_t source) {
	if (source == 0) {
		msg->np->has_source = 0;
	} else {
		msg->np->has_source = 1;
		msg->np->source = source;
	}
}

void
nmsg_message_set_operator(nmsg_message_t msg, uint32_t operator) {
	if (operator == 0) {
		msg->np->has_operator_ = 0;
	} else {
		msg->np->has_operator_ = 1;
		msg->np->operator_ = operator;
	}
}

void
nmsg_message_set_group(nmsg_message_t msg, uint32_t group) {
	if (group == 0) {
		msg->np->has_group = 0;
	} else {
		msg->np->has_group = 1;
		msg->np->group = group;
	}
}
