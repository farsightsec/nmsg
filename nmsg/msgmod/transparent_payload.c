/*
 * Copyright (c) 2009-2012 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

#ifdef HAVE_YAJL

#define add_yajl_string(g, s) do {                                              \
	yajl_gen_status g_status;                                               \
	g_status = yajl_gen_string(g, (const unsigned  char *) s, strlen(s));   \
	assert(g_status == yajl_gen_status_ok);                                 \
} while (0)

static void
callback_print_yajl_nmsg_strbuf(void *ctx, const char *str, size_t len)
{
        struct nmsg_strbuf *sb = (struct nmsg_strbuf *) ctx;
        nmsg_strbuf_append(sb, "%.*s", len, str);
}

nmsg_res
_nmsg_message_payload_to_json(struct nmsg_message *msg, char **json) {
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	yajl_gen g;
	yajl_gen_status status;
	int yajl_rc;
	struct nmsg_strbuf *sb;
	const char * ntop_status;

	size_t field_idx, n_fields;
	const char *field_name;
	nmsg_msgmod_field_type field_type;
	unsigned field_flags;

	size_t val_idx;
        unsigned val_enum;
        const char *str_enum;
        int val_bool;
	char str_ip[INET_ADDRSTRLEN];
	char str_ip6[INET6_ADDRSTRLEN];
        uint32_t val_uint32;
        uint64_t val_uint64;
        int32_t val_int32;
        int64_t val_int64;
        double val_double;
        const uint8_t *data;
        size_t data_len;

	sb = nmsg_strbuf_init();
	if (sb == NULL)
		return (nmsg_res_memfail);

	np = msg->np;

	g = yajl_gen_alloc(NULL);
	assert (g != NULL);

	yajl_rc = yajl_gen_config(g, yajl_gen_print_callback, callback_print_yajl_nmsg_strbuf, sb);
	assert (yajl_rc != 0);

	status = yajl_gen_map_open(g);
	assert(status == yajl_gen_status_ok);

	add_yajl_string(g, "time_sec");
	status = yajl_gen_integer(g, np->time_sec);
	assert(status == yajl_gen_status_ok);

	add_yajl_string(g, "time_nsec");
	status = yajl_gen_integer(g, np->time_nsec);
	assert(status == yajl_gen_status_ok);

	add_yajl_string(g, "vid");
	status = yajl_gen_integer(g, np->vid);
	assert(status == yajl_gen_status_ok);

	add_yajl_string(g, "msgtype");
	status = yajl_gen_integer(g, np->msgtype);
	assert(status == yajl_gen_status_ok);

	if (np->has_source) {
		add_yajl_string(g, "source");
		status = yajl_gen_integer(g, np->source);
		assert(status == yajl_gen_status_ok);
	}

	if (np->has_operator_) {
		add_yajl_string(g, "operator");
		status = yajl_gen_integer(g, np->operator_);
		assert(status == yajl_gen_status_ok);
	}

	if (np->has_group) {
		add_yajl_string(g, "group");
		status = yajl_gen_integer(g, np->group);
		assert(status == yajl_gen_status_ok);
	}

	add_yajl_string(g, "message");

	status = yajl_gen_map_open(g);
	assert(status == yajl_gen_status_ok);

	res = nmsg_message_get_num_fields(msg, &n_fields);
	if (res != nmsg_res_success) {
		// raise Exception, 'nmsg_message_get_num_fields() failed'
	}

	for (field_idx = 0; field_idx < n_fields; field_idx++) {
		res = nmsg_message_get_field_name(msg, field_idx, &field_name);
		if (res != nmsg_res_success) {
			continue;
		}

		/* Ensure that there is at least one value */
		res = nmsg_message_get_field_by_idx(msg, field_idx, 0, (void **) &data, &data_len);
		if (res == nmsg_res_success) {
			status = yajl_gen_string(g, (unsigned char *) field_name, strlen(field_name));
			assert(status == yajl_gen_status_ok);
		} else {
			continue;
		}

		res = nmsg_message_get_field_flags_by_idx(msg, field_idx, &field_flags);
		if (res != nmsg_res_success) {
			status = yajl_gen_null(g);
			assert(status == yajl_gen_status_ok);
			continue;
		}

		res = nmsg_message_get_field_type_by_idx(msg, field_idx, &field_type);
		if (res != nmsg_res_success) {
			status = yajl_gen_null(g);
			assert(status == yajl_gen_status_ok);
			continue;
		}

		if (field_flags & NMSG_MSGMOD_FIELD_REPEATED) {
			status = yajl_gen_array_open(g);
			assert(status == yajl_gen_status_ok);
		}

		val_idx = 0;

		while (1) {
			res = nmsg_message_get_field_by_idx(msg, field_idx, val_idx, (void **) &data, &data_len);
			if (res != nmsg_res_success) {
				break;
			}
			val_idx++;

			switch(field_type) {
				case nmsg_msgmod_ft_enum: {
					val_enum = data[0];
					res = nmsg_message_enum_value_to_name_by_idx(msg, field_idx, val_enum, &str_enum);
					if (res == nmsg_res_success) {
						status = yajl_gen_string(g, (const unsigned char*) str_enum, strlen(str_enum));
						assert(status == yajl_gen_status_ok);
					} else {
						status = yajl_gen_integer(g, val_enum);
						assert(status == yajl_gen_status_ok);
					}
					break;
				}
				case nmsg_msgmod_ft_bytes: {
					status = yajl_gen_string(g, (const unsigned char*) data, data_len);
					assert(status == yajl_gen_status_ok);
					break;
				}
				case nmsg_msgmod_ft_string:
				case nmsg_msgmod_ft_mlstring: {
					if (data_len > 0 && data[data_len-1]) {
						data_len--;
					}
					status = yajl_gen_string(g, (const unsigned char*)data, data_len);
					assert(status == yajl_gen_status_ok);
					break;
				}
				case nmsg_msgmod_ft_ip: {
					if (data_len == 4) {
						ntop_status = inet_ntop(AF_INET, data, str_ip, sizeof(str_ip));
						assert(ntop_status != NULL);
						status = yajl_gen_string(g, (const unsigned char*)str_ip, strlen(str_ip));
						assert(status == yajl_gen_status_ok);
					} else if (data_len == 16) {
						ntop_status = inet_ntop(AF_INET6, data, str_ip6, sizeof(str_ip6));
						assert(ntop_status != NULL);
						status = yajl_gen_string(g, (const unsigned char*)str_ip, strlen(str_ip));
						assert(status == yajl_gen_status_ok);
					} else {
						status = yajl_gen_number(g, (const char*)data, data_len);
						assert(status == yajl_gen_status_ok);
					}
					break;
				}
				case nmsg_msgmod_ft_uint16:
				case nmsg_msgmod_ft_uint32: {
					val_uint32 = ((uint32_t *)data)[0];
					status = yajl_gen_integer(g, val_uint32);
					assert(status == yajl_gen_status_ok);
					break;
				}
				case nmsg_msgmod_ft_uint64: {
					val_uint64 = ((uint64_t *)data)[0];
					status = yajl_gen_integer(g, val_uint64);
					assert(status == yajl_gen_status_ok);
					break;
				}
				case nmsg_msgmod_ft_int16:
				case nmsg_msgmod_ft_int32: {
					val_int32 = ((int32_t *)data)[0];
					status = yajl_gen_integer(g, val_int32);
					assert(status == yajl_gen_status_ok);
					break;
				}
				case nmsg_msgmod_ft_int64: {
					val_int64 = ((int64_t *)data)[0];
					status = yajl_gen_integer(g, val_int64);
					assert(status == yajl_gen_status_ok);
					break;
				}
				case nmsg_msgmod_ft_double: {
					val_double = ((double *)data)[0];
					status = yajl_gen_double(g, val_double);
					assert(status == yajl_gen_status_ok);
					break;
				}
				case nmsg_msgmod_ft_bool: {
					val_bool = ((int *)data)[0];
					status = yajl_gen_bool(g, val_bool);
					assert(status == yajl_gen_status_ok);
					break;
				}
				default: {
					status = yajl_gen_null(g);
					assert(status == yajl_gen_status_ok);
					break;
				}

			}

			if (! (field_flags & NMSG_MSGMOD_FIELD_REPEATED)) {
				break;
			}
		}

		if (field_flags & NMSG_MSGMOD_FIELD_REPEATED) {
			status = yajl_gen_array_close(g);
			assert(status == yajl_gen_status_ok);
		}

	}

	status = yajl_gen_map_close(g);
	assert(status == yajl_gen_status_ok);

	status = yajl_gen_map_close(g);
	assert(status == yajl_gen_status_ok);

	yajl_gen_reset(g, "");

	if (g != NULL) {
		yajl_gen_free(g);
	}

	*json = sb->data;
	free(sb);

	return (nmsg_res_success);
}
#else /* HAVE_YAJL */
nmsg_res
_nmsg_message_payload_to_json(struct nmsg_message *msg, char **pres) {
	return (nmsg_res_notimpl);
}
#endif /* HAVE_YAJL */
