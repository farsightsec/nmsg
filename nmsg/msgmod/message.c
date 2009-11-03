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

/* Forward. */

static void	reset_protobuf(struct nmsg_message *msg);

/* Export. */

struct nmsg_message *
nmsg_message_init(struct nmsg_msgmod *mod) {
	struct nmsg_message *msg;
	nmsg_res res;

	/* allocate space */
	msg = malloc(sizeof(*msg));
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
nmsg_message_dup(struct nmsg_message *msg) {
	struct nmsg_message *msgdup;

	/* allocate space */
	msgdup = calloc(1, sizeof(*msgdup));
	if (msgdup == NULL)
		return (NULL);

	/* initialize ->mod */
	msgdup->mod = msg->mod;

	/* initialize ->message */
	if (msg->message != NULL &&
	    msg->mod->type == nmsg_msgmod_type_transparent &&
	    msg->mod->pbdescr != NULL)
	{
		size_t msgsz = msg->mod->pbdescr->sizeof_message;

		msgdup->message = malloc(msgsz);
		if (msgdup->message == NULL) {
			free(msgdup);
			return (NULL);
		}
		memcpy(msgdup->message, msg->message, msgsz);
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
nmsg_message_from_payload(Nmsg__NmsgPayload *np) {
	struct nmsg_message *msg;

	/* allocate space */
	msg = malloc(sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	/* initialize ->mod */
	msg->mod = nmsg_msgmod_lookup(np->vid, np->msgtype);

	/* initialize ->message */
	msg->message = NULL;

	/* initialize ->np */
	msg->np = np;

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
	np->vid = mod->vendor.id;
	np->msgtype = mod->msgtype.id;
	np->time_sec = ts->tv_sec;
	np->time_nsec = ts->tv_nsec;
	np->has_payload = true;
	np->payload.data = data;
	np->payload.len = sz;

	msg = nmsg_message_from_payload(np);
	if (msg == NULL) {
		free(np);
		return (NULL);
	}
	return (msg);
}

nmsg_res
_nmsg_message_init_message(struct nmsg_message *msg) {
	if (msg->mod->type == nmsg_msgmod_type_transparent &&
	    msg->mod->pbdescr != NULL)
	{
		msg->message = calloc(1, msg->mod->pbdescr->sizeof_message);
		if (msg->message == NULL)
			return (nmsg_res_memfail);
		msg->message->descriptor = msg->mod->pbdescr;
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
	msg->np->vid = msg->mod->vendor.id;
	msg->np->msgtype = msg->mod->msgtype.id;
	nmsg_timespec_get(&ts);
	msg->np->time_sec = ts.tv_sec;
	msg->np->time_nsec = ts.tv_nsec;

	return (nmsg_res_success);
}

void
nmsg_message_destroy(struct nmsg_message **msg) {
	if ((*msg)->message != NULL)
		reset_protobuf(*msg);
	if ((*msg)->np != NULL) {
		if ((*msg)->np->payload.data != NULL)
			free((*msg)->np->payload.data);
		free((*msg)->np);
		(*msg)->np = NULL;
	}

	free((*msg)->message);
	free(*msg);
	*msg = NULL;
}

void
nmsg_message_clear(struct nmsg_message *msg) {
	if (msg->message != NULL)
		reset_protobuf(msg);
	if (msg->np == NULL)
		_nmsg_message_init_payload(msg);
}

nmsg_message_t
nmsg_message_unpack(struct nmsg_msgmod *mod, uint8_t *data, size_t len) {
	struct nmsg_message *msg;

	if (mod->type != nmsg_msgmod_type_transparent || mod->pbdescr == NULL)
		return (NULL);

	msg = malloc(sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	msg->mod = mod;

	msg->message = protobuf_c_message_unpack(mod->pbdescr, NULL, len, data);
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
		msg->message = protobuf_c_message_unpack(msg->mod->pbdescr, NULL,
							 msg->np->payload.len,
							 msg->np->payload.data);
		if (msg->message == NULL)
			return (nmsg_res_memfail);
	}

	return (nmsg_res_success);
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
		msg->np->has_payload = true;
		msg->np->payload.data = sbuf.data;
		msg->np->payload.len = sz;
	}

	return (nmsg_res_success);
}

nmsg_message_t
nmsg_message_unpack_payload(struct nmsg_msgmod *mod, Nmsg__NmsgPayload *np) {
	return (nmsg_message_unpack(mod, np->payload.data, np->payload.len));
}

Nmsg__NmsgPayload *
nmsg_message_get_payload(struct nmsg_message *msg) {
	return (msg->np);
}

/* Private. */

static void
reset_protobuf(struct nmsg_message *msg) {
	ProtobufCBinaryData *bdata;
	struct nmsg_msgmod_field *field;
	void *m;

	m = msg->message;

	for (field = msg->mod->fields; field->descr != NULL; field++) {
		if (field->descr->type == PROTOBUF_C_TYPE_BYTES) {
			if (PBFIELD_REPEATED(field)) {
				ProtobufCBinaryData **arr_bdata;
				size_t i, n;

				n = *PBFIELD_Q(m, field);
				if (n > 0) {
					arr_bdata = PBFIELD(m, field,
							    ProtobufCBinaryData *);
					for (i = 0; i < n; i++) {
						bdata = &(*arr_bdata)[i];
						if (bdata->data != NULL) {
							free(bdata->data);
							bdata->data = NULL;
							bdata->len = 0;
						}
					}
					free(*arr_bdata);
					*arr_bdata = NULL;
				}
			} else {
				bdata = PBFIELD(m, field, ProtobufCBinaryData);
				if (bdata->data != NULL) {
					free(bdata->data);
					bdata->data = NULL;
					bdata->len = 0;
				}
			}
		}
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL ||
		    field->descr->label == PROTOBUF_C_LABEL_REPEATED)
			*PBFIELD_Q(m, field) = 0;
	}
}
