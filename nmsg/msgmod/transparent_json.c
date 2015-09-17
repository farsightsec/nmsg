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

#ifdef HAVE_YAJL
nmsg_res
_nmsg_msgmod_json_to_message(void * val, struct nmsg_message *msg) {
	yajl_val message_v = (yajl_val) val;
	nmsg_res res;
	size_t n;
	struct nmsg_msgmod_field *field = NULL;

	for (n = 0; n < msg->mod->n_fields; n++) {
		const char* field_path[] = { (const char*) 0, (const char*)0 };
		yajl_val field_v;

		field = &msg->mod->fields[n];

		if (field->descr == NULL) {
			continue;
		}
		field_path[0] = field->descr->name;

		if (PBFIELD_REPEATED(field)) {
			yajl_val array_v;
			size_t v;

			array_v = yajl_tree_get(message_v, field_path, yajl_t_any);
			if (array_v) {
				if (! YAJL_IS_ARRAY(array_v)) {
					return (nmsg_res_parse_error);
				}

				for (v = 0; v < YAJL_GET_ARRAY(array_v)->len; v++) {
					field_v = YAJL_GET_ARRAY(array_v)->values[v];
					res = _nmsg_msgmod_json_to_payload_load(msg, field, n, v, field_v);
					if (res != nmsg_res_success) {
						return (res);
					}
				}
			}
		} else {
			field_v = yajl_tree_get(message_v, field_path, yajl_t_any);
			res = _nmsg_msgmod_json_to_payload_load(msg, field, n, 0, field_v);
			if (res != nmsg_res_success) {
				return (res);
			}
		}
	}

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_json_to_payload_load(struct nmsg_message *msg,
				  struct nmsg_msgmod_field *field,
                                  unsigned field_idx, unsigned val_idx,
                                  void * val)
{
	yajl_val field_v = (yajl_val) val;
	nmsg_res res;

	if (field_v == NULL) {
		return (nmsg_res_success);
	}

	if (field->parse != NULL) {
		if (YAJL_IS_STRING(field_v)) {
			char * str = YAJL_GET_STRING(field_v);
			uint8_t * ptr = NULL;
			size_t len = 0;

			res = field->parse(msg, field, str, (void*)&ptr, &len, "");
			if (res != nmsg_res_success) {
				return (res);
			}

			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, ptr, len);
			free (ptr);
			return (res);
		}
		return (nmsg_res_parse_error);
	}

	/* fields with custom printers and no parsers cannot be processed */
	if (field->print != NULL) {
		return (nmsg_res_failure);
	}

	switch (field->type) {
	case nmsg_msgmod_ft_bool: {
		protobuf_c_boolean b;

		if (YAJL_IS_TRUE(field_v)) {
			b = true;
		} else if (YAJL_IS_FALSE(field_v)) {
			b = false;
		} else if (YAJL_IS_INTEGER(field_v)) {
			b = YAJL_GET_INTEGER(field_v) != 0;
		} else if (YAJL_IS_STRING(field_v)) {
			char * str = YAJL_GET_STRING(field_v);
			if (strcasecmp("true", str)) {
				b = true;
			} else if (strcasecmp("false", str)) {
				b = false;
			} else {
				return (nmsg_res_parse_error);
			}
		}

		res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &b, sizeof(b));
		return (res);
		break;
	}
	case nmsg_msgmod_ft_bytes: {
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_enum: {
		ProtobufCEnumDescriptor *enum_descr;
		unsigned enum_value;

		enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;

		if (YAJL_IS_STRING(field_v)) {
			char * str = YAJL_GET_STRING(field_v);
			size_t i;

			for (i = 0; i < enum_descr->n_values; i++) {
				if (strcasecmp(enum_descr->values[i].name, str) == 0) {
					enum_value = enum_descr->values[i].value;
					break;
				}
			}
			if (i >= enum_descr->n_values) {
				return (nmsg_res_parse_error);
			}
		} else if (YAJL_IS_INTEGER(field_v)) {
			enum_value = YAJL_GET_INTEGER(field_v);
			if (enum_value < 0 || enum_value >= enum_descr->n_values) {
				return (nmsg_res_parse_error);
			}
		} else {
			return (nmsg_res_parse_error);
		}
		res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &enum_value, sizeof(enum_value));
		return (res);
		break;
	}
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		if (! YAJL_IS_STRING(field_v)) {
			return (nmsg_res_parse_error);
		}
		char * str = YAJL_GET_STRING(field_v);
		size_t len = strlen(str) + 1; /* \0 terminated */
		res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) str, len);
		return (res);
		break;
	}
	case nmsg_msgmod_ft_ip: {
		char addr[16];

		if (YAJL_IS_STRING(field_v)) {
			char * str = YAJL_GET_STRING(field_v);

			if (inet_pton(AF_INET, str, addr) == 1) {
				res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) addr, 4);
				return (res);
			} else if (inet_pton(AF_INET6, str, addr) == 1) {
				res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) addr, 16);
				return (res);
			}
		}
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_uint16: {
		uint32_t intval;

		if (YAJL_IS_INTEGER(field_v)) {
			if (YAJL_GET_INTEGER(field_v)> UINT16_MAX)
				return (nmsg_res_parse_error);
			intval = (uint32_t) YAJL_GET_INTEGER(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &intval, sizeof(intval));
			return (res);
		}
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		uint32_t intval;

		if (YAJL_IS_INTEGER(field_v)) {
			if (YAJL_GET_INTEGER(field_v)> UINT32_MAX)
				return (nmsg_res_parse_error);
			intval = (uint32_t) YAJL_GET_INTEGER(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &intval, sizeof(intval));
			return (res);
		}
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		uint64_t intval;

		if (YAJL_IS_INTEGER(field_v)) {
			intval = (uint64_t) YAJL_GET_INTEGER(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &intval, sizeof(intval));
			return (res);
		} else if (YAJL_IS_NUMBER(field_v)) {
			char * str = YAJL_GET_NUMBER(field_v);
			if (sscanf(str, "%" PRIu64, &intval)) {
				res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &intval, sizeof(intval));
				return (res);
			}
		}
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_int16: {
		int32_t intval;

		if (YAJL_IS_INTEGER(field_v)) {
			if (YAJL_GET_INTEGER(field_v) > INT16_MAX || YAJL_GET_INTEGER(field_v) < INT16_MIN)
				return (nmsg_res_parse_error);
			intval = (int32_t) YAJL_GET_INTEGER(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &intval, sizeof(intval));
			return (res);
		}
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_int32: {
		int32_t intval;

		if (YAJL_IS_INTEGER(field_v)) {
			if (YAJL_GET_INTEGER(field_v) > INT32_MAX || YAJL_GET_INTEGER(field_v) < INT32_MIN)
				return (nmsg_res_parse_error);
			intval = (int32_t) YAJL_GET_INTEGER(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &intval, sizeof(intval));
			return (res);
		}
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_int64: {
		int64_t intval;

		if (YAJL_IS_INTEGER(field_v)) {
			intval = (int64_t) YAJL_GET_INTEGER(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &intval, sizeof(intval));
			return (res);
		}
		return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_double: {
		double dval;

		if (YAJL_IS_DOUBLE(field_v)) {
			dval = YAJL_GET_DOUBLE(field_v);
			res = nmsg_message_set_field_by_idx(msg, field_idx, val_idx, (const uint8_t*) &dval, sizeof(dval));
			return (res);
		}
		return (nmsg_res_parse_error);
		break;
	}
	} /* switch */

	return (nmsg_res_failure);
}

#else /* HAVE_YAJL */
nmsg_res
_nmsg_msgmod_json_to_message(void * val, struct nmsg_message *msg) {
	return (nmsg_res_notimpl);
}

nmsg_res
_nmsg_msgmod_json_to_payload_load(struct nmsg_message *msg,
				  struct nmsg_msgmod_field *field,
                                  unsigned field_idx, unsigned val_idx,
                                  void * val)
{
	return (nmsg_res_notimpl);
}
#endif /* HAVE_YAJL */
