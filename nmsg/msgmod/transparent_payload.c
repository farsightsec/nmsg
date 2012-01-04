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

#include <stdlib.h>
#include <stdint.h>

#include "nmsg.h"
#include "private.h"

#include "transparent.h"

nmsg_res
_nmsg_message_payload_to_pres(struct nmsg_message *msg,
			      char **pres, const char *endline)
{
	ProtobufCMessage *m;
	nmsg_res res;
	size_t n;
	struct nmsg_msgmod_field *field;
	struct nmsg_strbuf *sb;

	/* unpack message */
	res = _nmsg_message_deserialize(msg);
	if (res != nmsg_res_success)
		return (res);
	m = msg->message;

	/* allocate pres str buffer */
	sb = nmsg_strbuf_init();
	if (sb == NULL)
		return (nmsg_res_memfail);

	/* convert each message field to presentation format */
	for (n = 0; n < msg->mod->n_fields; n++) {
		void *ptr;

		field = &msg->mod->plugin->fields[n];
		if (field->flags & (NMSG_MSGMOD_FIELD_HIDDEN | NMSG_MSGMOD_FIELD_NOPRINT))
			continue;

		if (field->get != NULL) {
			unsigned val_idx = 0;

			for (;;) {
				if (field->type == nmsg_msgmod_ft_ip ||
				    field->type == nmsg_msgmod_ft_bytes)
				{
					ProtobufCBinaryData bdata;
					res = field->get(msg, field, val_idx, (void **) &bdata.data, &bdata.len, msg->msg_clos);
					if (res != nmsg_res_success)
						break;
					ptr = &bdata;
				} else {
					res = field->get(msg, field, val_idx, &ptr, NULL, msg->msg_clos);
					if (res != nmsg_res_success)
						break;
				}
				res = _nmsg_message_payload_to_pres_load(msg, field, ptr, sb, endline);
				if (res != nmsg_res_success)
					goto err;
				val_idx += 1;
			}
		} else if (PBFIELD_ONE_PRESENT(m, field)) {
			ptr = PBFIELD(m, field, void);

			res = _nmsg_message_payload_to_pres_load(msg, field, ptr, sb, endline);
			if (res != nmsg_res_success)
				goto err;
		} else if (PBFIELD_REPEATED(field)) {
			size_t i, n_entries;

			n_entries = *PBFIELD_Q(m, field);
			for (i = 0; i < n_entries; i++) {
				ptr = PBFIELD(m, field, void);
				char *array = *(char **) ptr;
				size_t siz = sizeof_elt_in_repeated_array(field->descr->type);

				res = _nmsg_message_payload_to_pres_load(msg, field, &array[i * siz], sb, endline);
				if (res != nmsg_res_success)
					goto err;
			}
		}
	}

	/* cleanup */
	*pres = sb->data;
	free(sb);

	return (nmsg_res_success);

err:
	nmsg_strbuf_destroy(&sb);
	return (res);
}

nmsg_res
_nmsg_message_payload_to_pres_load(struct nmsg_message *msg,
				  struct nmsg_msgmod_field *field, void *ptr,
				  struct nmsg_strbuf *sb, const char *endline)
{
	ProtobufCBinaryData *bdata;
	unsigned i;

	if (field->print != NULL) {
		if (field->type == nmsg_msgmod_ft_uint16 ||
		    field->type == nmsg_msgmod_ft_int16)
		{
			uint16_t val;
			uint32_t val32;
			memcpy(&val32, ptr, sizeof(uint32_t));
			val = (uint16_t) val32;
			return (field->print(msg, field, &val, sb, endline));
		}
		return (field->print(msg, field, ptr, sb, endline));
	}

	switch (field->type) {
	case nmsg_msgmod_ft_bytes:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s: <BYTE ARRAY LEN=%zd>%s",
				   field->name,
				   bdata->len,
				   endline);
		break;
	case nmsg_msgmod_ft_string:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s: %s%s",
				   field->name,
				   bdata->data,
				   endline);
		break;
	case nmsg_msgmod_ft_mlstring:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s:%s%s.%s",
				   field->name,
				   endline,
				   bdata->data,
				   endline);
		break;
	case nmsg_msgmod_ft_bool: {
		protobuf_c_boolean *b = (protobuf_c_boolean *) ptr;
		nmsg_strbuf_append(sb, "%s: %s%s",
				   field->name,
				   *b ? "True" : "False",
				   endline);
		break;
	}
	case nmsg_msgmod_ft_enum: {
		ProtobufCEnumDescriptor *enum_descr;
		bool enum_found;
		unsigned enum_value;

		enum_found = false;
		enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;

		enum_value = *((unsigned *) ptr);
		for (i = 0; i < enum_descr->n_values; i++) {
			if ((unsigned) enum_descr->values[i].value == enum_value) {
				nmsg_strbuf_append(sb, "%s: %s%s",
						   field->name,
						   enum_descr->values[i].name,
						   endline);
				enum_found = true;
			}
		}
		if (enum_found == false) {
			nmsg_strbuf_append(sb, "%s: <UNKNOWN ENUM VAL=%u>%s",
					   field->name, enum_value,
					   endline);
		}
		break;
	}
	case nmsg_msgmod_ft_ip: {
		char sip[INET6_ADDRSTRLEN];

		bdata = (ProtobufCBinaryData *) ptr;
		if (bdata->len == 4) {
			if (inet_ntop(AF_INET, bdata->data, sip, sizeof(sip))) {
				nmsg_strbuf_append(sb, "%s: %s%s",
						   field->name,
						   sip, endline);
			}
		} else if (bdata->len == 16) {
			if (inet_ntop(AF_INET6, bdata->data, sip, sizeof(sip))) {
				nmsg_strbuf_append(sb, "%s: %s%s",
						   field->name,
						   sip, endline);
			}
		} else {
			nmsg_strbuf_append(sb, "%s: <INVALID IP len=%zd>%s",
					   field->name, bdata->len,
					   endline);
		}
		break;
	}
	case nmsg_msgmod_ft_uint16: {
		uint32_t val;
		memcpy(&val, ptr, sizeof(uint32_t));
		nmsg_strbuf_append(sb, "%s: %hu%s", field->name, (uint16_t) val, endline);
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		uint32_t val;
		memcpy(&val, ptr, sizeof(uint32_t));
		nmsg_strbuf_append(sb, "%s: %u%s", field->name, val, endline);
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		uint64_t val;
		memcpy(&val, ptr, sizeof(uint64_t));
		nmsg_strbuf_append(sb, "%s: %" PRIu64 "%s", field->name, val, endline);
		break;
	}
	case nmsg_msgmod_ft_int16: {
		int32_t val;
		memcpy(&val, ptr, sizeof(int32_t));
		nmsg_strbuf_append(sb, "%s: %hd%s", field->name, (int16_t) val, endline);
		break;
	}
	case nmsg_msgmod_ft_int32: {
		int32_t val;
		memcpy(&val, ptr, sizeof(int32_t));
		nmsg_strbuf_append(sb, "%s: %d%s", field->name, val, endline);
		break;
	}
	case nmsg_msgmod_ft_int64: {
		int64_t val;
		memcpy(&val, ptr, sizeof(int64_t));
		nmsg_strbuf_append(sb, "%s: %" PRIi64 "%s", field->name, val, endline);
		break;
	}
	case nmsg_msgmod_ft_double: {
		double val;
		memcpy(&val, ptr, sizeof(double));
		nmsg_strbuf_append(sb, "%s: %f%s", field->name, val, endline);
		break;
	}
	} /* end switch */

	return (nmsg_res_success);
}
