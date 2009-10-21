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
	struct timespec ts;
	struct nmsg_message *msg;

	/* only valid for properly initialized transparent modules */
	if (mod->type != nmsg_msgmod_type_transparent || mod->pbdescr == NULL)
		return (NULL);

	/* allocate space */
	msg = malloc(sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	/* initialize ->mod */
	msg->mod = mod;

	/* initialize ->message */
	msg->message = calloc(1, mod->pbdescr->sizeof_message);
	if (msg->message == NULL) {
		free(msg);
		return (NULL);
	}
	msg->message->descriptor = mod->pbdescr;

	/* initialize ->payload */
	nmsg__nmsg_payload__init(&msg->payload);
	msg->payload.vid = mod->vendor.id;
	msg->payload.msgtype = mod->msgtype.id;
	nmsg_timespec_get(&ts);
	msg->payload.time_sec = ts.tv_sec;
	msg->payload.time_nsec = ts.tv_nsec;

	return (msg);

}

void
nmsg_message_destroy(struct nmsg_message **msg) {
	nmsg_message_clear(*msg);

	free((*msg)->message);
	free(*msg);
	*msg = NULL;
}

void
nmsg_message_clear(struct nmsg_message *msg) {
	_nmsg_msgmod_message_reset(msg->mod, msg->message);
	if (msg->payload.has_payload && msg->payload.payload.data != NULL)
		free(msg->payload.payload.data);
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
_nmsg_message_serialize(struct nmsg_message *msg) {
	ProtobufCBufferSimple sbuf;
	size_t sz;

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.data = malloc(1024);
	if (sbuf.data == NULL)
		return (nmsg_res_memfail);
	sbuf.must_free_data = 1;
	sbuf.alloced = 1024;

	sz = protobuf_c_message_pack_to_buffer((ProtobufCMessage *) msg->message,
					       (ProtobufCBuffer *) &sbuf);
	msg->payload.has_payload = true;
	msg->payload.payload.data = sbuf.data;
	msg->payload.payload.len = sz;

	return (nmsg_res_success);
}

nmsg_message_t
nmsg_message_unpack_payload(struct nmsg_msgmod *mod, Nmsg__NmsgPayload *np) {
	return (nmsg_message_unpack(mod, np->payload.data, np->payload.len));
}

nmsg_res
nmsg_message_get_num_fields(struct nmsg_message *msg, size_t *n_fields) {
	if (msg->mod->type != nmsg_msgmod_type_transparent ||
	    msg->mod->pbdescr == NULL)
		return (nmsg_res_failure);

	*n_fields = msg->mod->pbdescr->n_fields;
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field_name(struct nmsg_message *msg, unsigned idx,
			    const char **field_name)
{
	struct nmsg_msgmod_field *field;

	if (msg->mod->type != nmsg_msgmod_type_transparent ||
	    msg->mod->pbdescr == NULL)
		return (nmsg_res_failure);

	if (idx > msg->mod->pbdescr->n_fields - 1)
		return (nmsg_res_failure);

	field = &msg->mod->fields[idx];
	*field_name = field->name;
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field_idx(struct nmsg_message *msg, const char *field_name,
			   unsigned *idx)
{
	struct nmsg_msgmod_field *field;

	if (msg->mod->type != nmsg_msgmod_type_transparent ||
	    msg->mod->pbdescr == NULL)
		return (nmsg_res_failure);

	field = _nmsg_msgmod_lookup_field(msg->mod, field_name);
	if (field == NULL)
		return (nmsg_res_failure);

	*idx = field - &msg->mod->fields[0];
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_num_field_values_by_idx(struct nmsg_message *msg,
					 unsigned field_idx,
					 size_t *n_field_values)
{
	struct nmsg_msgmod_field *field;

	if (msg->mod->type != nmsg_msgmod_type_transparent ||
	    msg->mod->pbdescr == NULL)
		return (nmsg_res_failure);

	if (field_idx > msg->mod->pbdescr->n_fields - 1)
		return (nmsg_res_failure);

	field = &msg->mod->fields[field_idx];

	if (field->descr->label == PROTOBUF_C_LABEL_REQUIRED) {
		*n_field_values = 1;
		return (nmsg_res_success);
	} else if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL ||
		   field->descr->label == PROTOBUF_C_LABEL_REPEATED)
	{
		*n_field_values = *PBFIELD_Q(msg->message, field);
		return (nmsg_res_success);
	}

	return (nmsg_res_failure);
}

nmsg_res
nmsg_message_get_num_field_values(struct nmsg_message *msg,
				  const char *field_name,
				  size_t *n_field_values)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_get_num_field_values_by_idx(msg, field_idx, n_field_values));
	else
		return (nmsg_res_failure);
}

nmsg_res
nmsg_message_get_field_type_by_idx(struct nmsg_message *msg,
				   unsigned field_idx,
				   nmsg_msgmod_field_type *type)
{
	struct nmsg_msgmod_field *field;

	if (msg->mod->type != nmsg_msgmod_type_transparent ||
	    msg->mod->pbdescr == NULL)
		return (nmsg_res_failure);

	if (field_idx > msg->mod->pbdescr->n_fields - 1)
		return (nmsg_res_failure);

	field = &msg->mod->fields[field_idx];

	*type = field->type;
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field_type(struct nmsg_message *msg,
			    const char *field_name,
			    nmsg_msgmod_field_type *type)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_get_field_type_by_idx(msg, field_idx, type));
	else
		return (nmsg_res_failure);
}

nmsg_res
nmsg_message_set_field_by_idx(struct nmsg_message *msg, unsigned field_idx,
			      unsigned val_idx,
			      const uint8_t *data, size_t len)
{
	char **parray;
	int *qptr;
	size_t sz;
	ssize_t msz;
	struct nmsg_msgmod_field *field;
	void *ptr;

	if (msg->mod->type != nmsg_msgmod_type_transparent ||
	    msg->mod->pbdescr == NULL)
		return (nmsg_res_failure);

	if (field_idx > msg->mod->pbdescr->n_fields - 1)
		return (nmsg_res_failure);

	field = &msg->mod->fields[field_idx];

	switch (field->type) {
	case nmsg_msgmod_ft_enum:
		msz = 4;
		break;

	case nmsg_msgmod_ft_ip:
		if (len == 4)
			msz = 4;
		else if (len == 16)
			msz = 16;
		break;

	case nmsg_msgmod_ft_int16:
	case nmsg_msgmod_ft_uint16:
		msz = 2;
		break;

	case nmsg_msgmod_ft_int32:
	case nmsg_msgmod_ft_uint32:
		msz = 4;
		break;

	case nmsg_msgmod_ft_int64:
	case nmsg_msgmod_ft_uint64:
		msz = 8;
		break;
	
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring:
		msz = len;
		break;

	default:
		return (nmsg_res_failure);
	}

	qptr = PBFIELD_Q(msg->message, field);

	switch (field->descr->label) {
	case PROTOBUF_C_LABEL_REPEATED:
		sz = sizeof_elt_in_repeated_array(field->descr->type);

		if (val_idx > (unsigned) *qptr) {
			return (nmsg_res_failure);
		} else if (val_idx == (unsigned) *qptr) {
			size_t bytes_needed, bytes_used;

			bytes_used = (*qptr) * sz;
			*qptr += 1;
			bytes_needed = (*qptr) * sz;

			assert(bytes_used < bytes_needed);

			parray = (char **) PBFIELD(msg->message, field, void);

			ptr = realloc(*parray, bytes_needed);
			if (ptr == NULL) {
				free(*parray);
				*qptr = 0;
				*parray = NULL;
				return (nmsg_res_memfail);
			}
			*parray = ptr;

			/* scrub the uninitialized part of the allocation */
			memset(((char *) ptr) + bytes_used, 0, bytes_needed - bytes_used);
		}
		parray = (char **) PBFIELD(msg->message, field, void);
		ptr = *parray + (sz * val_idx);
		break;
	case PROTOBUF_C_LABEL_OPTIONAL:
		if (val_idx == 0)
			*qptr = 1;
		/* FALLTHROUGH */
	case PROTOBUF_C_LABEL_REQUIRED:
		if (val_idx > 0)
			return (nmsg_res_failure);
		ptr = PBFIELD(msg->message, field, void);
		break;
	}

	assert(ptr != NULL);

	switch (field->type) {
	case nmsg_msgmod_ft_ip:
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		ProtobufCBinaryData *bdata;
		bdata = ptr;
		if (bdata->data != NULL)
			free(bdata->data);
		bdata->data = malloc(len);
		if (bdata->data == NULL)
			return (nmsg_res_memfail);
		bdata->len = len;
		fprintf(stderr, "made a bdata->data allocation at %p len=%zd\n", bdata->data, bdata->len);
		memcpy(bdata->data, data, len);
		break;
	}
	case nmsg_msgmod_ft_enum: {
		unsigned val, *pval;
		pval = ptr;
		memcpy(&val, data, msz);
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_int16: {
		int16_t val, *pval;
		pval = ptr;
		memcpy(&val, data, msz);
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_uint16: {
		uint16_t val, *pval;
		pval = ptr;
		memcpy(&val, data, msz);
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_int32: {
		int32_t val, *pval;
		pval = ptr;
		memcpy(&val, data, msz);
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		uint32_t val, *pval;
		pval = ptr;
		memcpy(&val, data, msz);
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_int64: {
		int64_t val, *pval;
		pval = ptr;
		memcpy(&val, data, msz);
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		uint64_t val, *pval;
		pval = ptr;
		memcpy(&val, data, msz);
		*pval = val;
		break;
	}
	default:
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

nmsg_res
nmsg_message_set_field(nmsg_message_t msg, const char *field_name,
		       unsigned val_idx,
		       const uint8_t *data, size_t len)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_set_field_by_idx(msg, field_idx, val_idx, data, len));
	else
		return (nmsg_res_failure);
}
