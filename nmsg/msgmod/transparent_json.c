/*
 * Copyright (c) 2015 by Farsight Security, Inc.
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

#ifdef HAVE_JSON_C
nmsg_res
_nmsg_msgmod_json_to_message(void *val, struct nmsg_message *msg) {
	struct json_object *node = (struct json_object *)val;
	nmsg_res res;

	for (size_t n = 0; n < msg->mod->n_fields; n++) {
		struct nmsg_msgmod_field *field = NULL;
		char field_path[1024];
		struct json_object *field_v = NULL;

		field = &msg->mod->fields[n];

		/* skip virtual fields */
		if (field->descr == NULL)
			continue;

		field_path[0] = '/';
		field_path[1] = '\0';
		strncat(&field_path[1], field->descr->name, sizeof(field_path) - 2);

		if (PBFIELD_REPEATED(field)) {
			struct json_object *array_v = NULL;

			if (json_pointer_get(node, field_path, &array_v) == 0) {

				if (!json_object_is_type(array_v, json_type_array))
					return nmsg_res_parse_error;

				for (size_t v = 0; v < json_object_array_length(array_v); v++) {
					field_v = json_object_array_get_idx(array_v, v);
					assert(field_v != NULL);
					res = _nmsg_msgmod_json_to_payload_load(msg, field, n, v, field_v);
					if (res != nmsg_res_success)
						return res;
				}
			}
		} else {
			json_pointer_get(node, field_path, &field_v);

			res = _nmsg_msgmod_json_to_payload_load(msg, field, n, 0, field_v);
			if (res != nmsg_res_success) {
				return res;
			}
		}
	}

	return nmsg_res_success;
}

nmsg_res
_nmsg_msgmod_json_to_payload_load(struct nmsg_message *msg,
				  struct nmsg_msgmod_field *field,
				  unsigned field_idx, unsigned val_idx,
				  void *val)
{
	struct json_object *field_v = (struct json_object *)val;
	nmsg_res res;

	if (field_v == NULL)
		return (nmsg_res_success);

	if (field->parse != NULL) {
		if (json_object_is_type(field_v, json_type_string)) {
			const char *str = json_object_get_string(field_v);
			uint8_t *ptr = NULL;
			size_t len = 0;

			res = field->parse(msg, field, str, (void *) &ptr, &len, "");
			if (res != nmsg_res_success)
				return res;

			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, ptr, len);
			free(ptr);
			return (res);
		}
		return nmsg_res_parse_error;
	}

	switch (field->type) {
	case nmsg_msgmod_ft_bool: {
		protobuf_c_boolean b;

		if (json_object_is_type(field_v, json_type_boolean)) {
			b = json_object_get_boolean(field_v);
		} else if (json_object_is_type(field_v, json_type_int)) {
			b = json_object_get_int(field_v) != 0;
		} else if (json_object_is_type(field_v, json_type_string)) {
			const char *str = json_object_get_string(field_v);
			if (strcasecmp("true", str) == 0) {
				b = true;
			} else if (strcasecmp("false", str) == 0) {
				b = false;
			} else {
				return nmsg_res_parse_error;
			}
		}

		res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
			(const uint8_t *) &b, sizeof(b));
		return res;
		break;
	}
	case nmsg_msgmod_ft_bytes: {
		if (json_object_is_type(field_v, json_type_object)) {
			field_v = json_object_object_get(field_v, "b64");
			if (field_v == NULL) {
				return nmsg_res_parse_error;
			}
		}

		if (json_object_is_type(field_v, json_type_string)) {
			const char *b64_str = json_object_get_string(field_v);
			char *s;
			size_t b64_str_len, len;
			base64_decodestate b64;

			base64_init_decodestate(&b64);
			b64_str_len = strlen(b64_str);
			s = malloc(b64_str_len + 1);
			if (s == NULL)
				return nmsg_res_memfail;
			len = base64_decode_block(b64_str, b64_str_len, s, &b64);

			res = nmsg_message_set_field_by_idx(msg, field_idx,
				    val_idx, (const uint8_t *) s, len);
			free(s);
			return (res);
		} else {
			return (nmsg_res_parse_error);
		}
		break;
	}
	case nmsg_msgmod_ft_enum: {
		ProtobufCEnumDescriptor *enum_descr;
		unsigned enum_value;

		enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;

		if (json_object_is_type(field_v, json_type_string)) {
			const char *str = json_object_get_string(field_v);
			size_t i;

			for (i = 0; i < enum_descr->n_values; i++) {
				if (strcasecmp(enum_descr->values[i].name, str) == 0) {
					enum_value = enum_descr->values[i].value;
					break;
				}
			}
			if (i >= enum_descr->n_values) {
				return nmsg_res_parse_error;
			}
		} else if (json_object_is_type(field_v, json_type_int)) {
			enum_value = json_object_get_int(field_v);
			if (enum_value >= enum_descr->n_values)
				return nmsg_res_parse_error;
		} else {
			return nmsg_res_parse_error;
		}
		res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
			(const uint8_t *) &enum_value, sizeof(enum_value));
		return res;
		break;
	}
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		if (!json_object_is_type(field_v, json_type_string)) {
			return nmsg_res_parse_error;
		}
		const char *str = json_object_get_string(field_v);
		size_t len = strlen(str) + 1;	/* \0 terminated */
		res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
			(const uint8_t *) str, len);
		return res;
		break;
	}
	case nmsg_msgmod_ft_ip: {
		char addr[16] = {0};

		if (json_object_is_type(field_v, json_type_string)) {
			const char *str = json_object_get_string(field_v);

			if (inet_pton(AF_INET, str, addr) == 1) {
				return nmsg_message_set_field_by_idx(msg, field_idx,
					val_idx, (const uint8_t *) addr, 4);
			} else if (inet_pton(AF_INET6, str, addr) == 1) {
				return nmsg_message_set_field_by_idx(msg, field_idx,
					val_idx, (const uint8_t *) addr, 16);
			}
		} else if (json_object_is_type(field_v, json_type_null)) {
				res = nmsg_message_set_field_by_idx(msg,
					    field_idx, val_idx, (const uint8_t *) addr, 0);
				return (res);
		}
		return nmsg_res_parse_error;
		break;
	}
	case nmsg_msgmod_ft_uint16: {
		uint32_t intval;

		if (json_object_is_type(field_v, json_type_int)) {
			if (json_object_get_int(field_v) > UINT16_MAX)
				return nmsg_res_parse_error;
			intval = (uint32_t) json_object_get_int(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
				(const uint8_t *) &intval, sizeof(intval));
			return res;
		}
		return nmsg_res_parse_error;
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		uint32_t intval;

		if (json_object_is_type(field_v, json_type_int)) {
			if (json_object_get_int64(field_v) > UINT32_MAX)
				return nmsg_res_parse_error;
			intval = (uint32_t) json_object_get_int64(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
				(const uint8_t *) &intval, sizeof(intval));
			return res;
		}
		return nmsg_res_parse_error;
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		uint64_t intval;

		if (json_object_is_type(field_v, json_type_int)) {
			intval = (uint64_t) json_object_get_int64(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
				(const uint8_t *) &intval, sizeof(intval));
			return res;
		} else if (json_object_is_type(field_v, json_type_string)) {
			const char *str = json_object_get_string(field_v);
			if (sscanf(str, "%" PRIu64, &intval)) {
				res = nmsg_message_set_field_by_idx(msg, field_idx,
					val_idx, (const uint8_t *) &intval, sizeof(intval));
				return res;
			}
		}
		return nmsg_res_parse_error;
		break;
	}
	case nmsg_msgmod_ft_int16: {
		int32_t intval;

		if (json_object_is_type(field_v, json_type_int)) {
			if (json_object_get_int(field_v) > INT16_MAX || json_object_get_int(field_v) < INT16_MIN) {
				return nmsg_res_parse_error;
			}
			intval = (int32_t) json_object_get_int(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
				(const uint8_t *) &intval, sizeof(intval));
			return res;
		}
		return nmsg_res_parse_error;
		break;
	}
	case nmsg_msgmod_ft_int32: {
		int32_t intval;

		if (json_object_is_type(field_v, json_type_int)) {
			if (json_object_get_int64(field_v) > INT32_MAX || json_object_get_int64(field_v) < INT32_MIN) {
				return nmsg_res_parse_error;
			}
			intval = (int32_t) json_object_get_int64(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
				(const uint8_t *) &intval, sizeof(intval));
			return res;
		}
		return nmsg_res_parse_error;
		break;
	}
	case nmsg_msgmod_ft_int64: {
		int64_t intval;

		if (json_object_is_type(field_v, json_type_int)) {
			intval = (int64_t) json_object_get_int64(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx,
				(const uint8_t *) &intval, sizeof(intval));
			return res;
		}
		return nmsg_res_parse_error;
		break;
	}
	case nmsg_msgmod_ft_double: {
		double dval;

		if (json_object_is_type(field_v, json_type_double)) {
			dval = json_object_get_double(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx,
				val_idx, (const uint8_t *) &dval, sizeof(dval));
			return res;
		}
		return nmsg_res_parse_error;
		break;
	}
	} /* switch */

	return nmsg_res_failure;
}

#else /* HAVE_JSON_C */
nmsg_res
_nmsg_msgmod_json_to_message(__attribute__((unused)) void *val,
                             __attribute__((unused)) struct nmsg_message *msg) {
	return (nmsg_res_notimpl);
}

nmsg_res
_nmsg_msgmod_json_to_payload_load(__attribute__((unused)) struct nmsg_message *msg,
				  __attribute__((unused)) struct nmsg_msgmod_field *field,
				  __attribute__((unused)) unsigned field_idx,
				  __attribute__((unused)) unsigned val_idx,
				  __attribute__((unused)) void *val)
{
	return (nmsg_res_notimpl);
}
#endif /* HAVE_JSON_C */
