/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2009-2017, 2019 by Farsight Security, Inc.
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
	struct nmsg_strbuf_storage sbs;
	/* allocate pres str buffer */
	struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);

	/* unpack message */
	res = _nmsg_message_deserialize(msg);
	if (res != nmsg_res_success)
		return (res);
	m = msg->message;

	/* convert each message field to presentation format */
	for (n = 0; n < msg->mod->n_fields; n++) {
		void *ptr;

		field = &msg->mod->plugin->fields[n];
		if (field->flags & (NMSG_MSGMOD_FIELD_HIDDEN | NMSG_MSGMOD_FIELD_NOPRINT))
			continue;

		if (field->get != NULL) {
			unsigned val_idx = 0;

			for (;;) {
				ProtobufCBinaryData bdata;

				if (field->type == nmsg_msgmod_ft_ip ||
				    field->type == nmsg_msgmod_ft_bytes)
				{
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
	*pres = _nmsg_strbuf_detach(sb);

	return (nmsg_res_success);

err:
	_nmsg_strbuf_destroy(&sbs);
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

	if (field->format != NULL && ((field->flags & NMSG_MSGMOD_FIELD_FORMAT_RAW) == 0)) {
		nmsg_res res;
		struct nmsg_strbuf_storage sbs_tmp;
		struct nmsg_strbuf *sb_tmp = _nmsg_strbuf_init(&sbs_tmp);

		if (field->type == nmsg_msgmod_ft_uint16 ||
		    field->type == nmsg_msgmod_ft_int16)
		{
			uint16_t val;
			uint32_t val32;
			memcpy(&val32, ptr, sizeof(uint32_t));
			val = (uint16_t) val32;
			res = field->format(msg, field, &val, sb_tmp, endline);
		} else {
			res = field->format(msg, field, ptr, sb_tmp, endline);
		}

		if (res == nmsg_res_success)
			nmsg_strbuf_append(sb, "%s: %s%s", field->name, sb_tmp->data, endline);

		_nmsg_strbuf_destroy(&sbs_tmp);

		return res;
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
		nmsg_strbuf_append(sb, "%s: %.*s%s",
				   field->name,
				   bdata->len,
				   bdata->data,
				   endline);
		break;
	case nmsg_msgmod_ft_mlstring:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s:%s%.*s.%s",
				   field->name,
				   endline,
				   bdata->len,
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
				break;
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
			if (fast_inet4_ntop(bdata->data, sip, sizeof(sip))) {
				nmsg_strbuf_append(sb, "%s: %s%s",
						   field->name,
						   sip, endline);
			}
		} else if (bdata->len == 16) {
			if (fast_inet6_ntop(bdata->data, sip, sizeof(sip))) {
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

static nmsg_res
_nmsg_nmsg_mod_ip_to_string(ProtobufCBinaryData *bdata, bool enquote,
			    struct nmsg_strbuf *g) {
	char sip[INET6_ADDRSTRLEN];
	int family = 0;

	if (bdata->data == NULL) {
		append_json_value_null(g);
		return nmsg_res_success;
	}

	if (bdata->len == 4) {
		family = AF_INET;
	} else if (bdata->len == 16) {
		family = AF_INET6;
	}

	if (family && fast_inet_ntop(family, bdata->data, sip, sizeof(sip))) {
		if (enquote)
			append_json_value_string_noescape(g, sip, strlen(sip));
		else
			return nmsg_strbuf_append_str(g, sip, strlen(sip));
	} else {
		append_json_value_null(g);
	}

	return nmsg_res_success;
}

/*
 * The determination of a key value from a named nmsg message field is as follows:
 *
 * 1. If the field doesn't exist, return an error.
 * 2. If the field data can't be retrieved, return an empty buffer.
 * 3. If the field has a formatter function, return the raw string returned by it.
 * 4. If the field is an enum value, return the corresponding canonical string value.
 *    If the enum value has no string mapping, return a numeric (string) representation.
 * 5. For strings, return the ASCII string value without any terminating NUL byte.
 * 6. For IP (v4 or v6) addresses, return the dotted representational string value.
 * 7. For all other simple numeric primitive types, return a numeric (string) representation.
 * 8. For all other values (including byte sequences), return the raw binary payload field data.
 */
nmsg_res
_nmsg_message_payload_get_field_value_as_key(nmsg_message_t msg, const char *field_name, struct nmsg_strbuf *sb) {
	nmsg_res res;
	struct nmsg_msgmod_field *field;
	ProtobufCBinaryData bdata;

	field = _nmsg_msgmod_lookup_field(msg->mod, field_name);
	if (field == NULL)
		return nmsg_res_failure;

	res = nmsg_message_get_field(msg, field_name, 0, (void **) &bdata.data, &bdata.len);
	if (res != nmsg_res_success) {
		/* if field is present but no data, return empty buffer */
		nmsg_strbuf_reset(sb);
		*sb->data = '\0';
		return nmsg_res_success;
	}

	if (field->format != NULL) {
		char *endline = "";

		if (field->type == nmsg_msgmod_ft_uint16 || field->type == nmsg_msgmod_ft_int16) {
			uint16_t val;
			uint32_t val32;
			memcpy(&val32, bdata.data, sizeof(uint32_t));
			val = (uint16_t) val32;
			res = field->format(msg, field, &val, sb, endline);
		} else {
			res = field->format(msg, field, (void *) &bdata, sb, endline);
		}

		return res;
	} else if (PBFIELD_ONE_PRESENT(msg->message, field)) {

		if (field->type == nmsg_msgmod_ft_enum) {
			ProtobufCEnumDescriptor *enum_descr;
			bool enum_found = false;
			unsigned enum_value;

			enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;
			enum_value = *((unsigned *) bdata.data);

			for (unsigned i = 0; i < enum_descr->n_values; i++) {
				if ((unsigned) enum_descr->values[i].value == enum_value) {
					res = nmsg_strbuf_append_str(sb, enum_descr->values[i].name,
								     strlen(enum_descr->values[i].name));
					enum_found = true;
					break;
				}
			}

			if (!enum_found)
				append_json_value_int(sb, enum_value);

			return res;
		} else {
			switch(field->type) {
				/* Trim trailing nul byte present in strings. */
				case nmsg_msgmod_ft_string:
				case nmsg_msgmod_ft_mlstring:
					if (bdata.len > 0 && bdata.data[bdata.len - 1] == 0)
						bdata.len--;
					break;
				case nmsg_msgmod_ft_bytes:
					break;
				case nmsg_msgmod_ft_ip:
					return _nmsg_nmsg_mod_ip_to_string(&bdata, false, sb);
				default:
					return _nmsg_message_payload_to_json_load(msg, field, bdata.data, sb);
			}
		}
	}

	return nmsg_strbuf_append_str(sb, (const char *) bdata.data, bdata.len);
}

nmsg_res
_nmsg_message_payload_to_json(nmsg_output_t output, struct nmsg_message *msg, struct nmsg_strbuf *sb) {
	Nmsg__NmsgPayload *np;
	ProtobufCMessage *m;
	nmsg_res res;
	char sb_tmp[256];
	size_t sb_tmp_len;

	struct nmsg_msgmod_field *field;
	const char *vname, *mname;
	uint32_t oper_val = 0, group_val = 0, source_val = 0;

	struct tm tm;
	time_t t;
	char when[]="XXXX-XX-XX XX:XX:XX.XXXXXXXXX";
	size_t fidx = 0;

	/* unpack message */
	res = _nmsg_message_deserialize(msg);
	if (res != nmsg_res_success)
		return (res);
	m = msg->message;

	np = msg->np;

	nmsg_strbuf_append_str(sb, "{", 1);

	t = np->time_sec;
	gmtime_r(&t, &tm);

	num_to_str(1900 + tm.tm_year, 4, when);
	num_to_str(1 + tm.tm_mon, 2, when + 5);
	num_to_str(tm.tm_mday, 2, when + 8);
	num_to_str(tm.tm_hour, 2, when + 11);
	num_to_str(tm.tm_min, 2, when + 14);
	num_to_str(tm.tm_sec, 2, when + 17);
	num_to_str(np->time_nsec, 9, when + 20);

	declare_json_value(sb, "time", true);
	append_json_value_string(sb, when, sizeof(when) - 1);

	vname = nmsg_msgmod_vid_to_vname(np->vid);
	if (vname == NULL)
		vname = "(unknown)";

	declare_json_value(sb, "vname", false);
	append_json_value_string(sb, vname, strlen(vname));

	mname = nmsg_msgmod_msgtype_to_mname(np->vid, np->msgtype);
	if (mname == NULL)
		mname = "(unknown)";

	declare_json_value(sb, "mname", false);
	append_json_value_string(sb, mname, strlen(mname));

	if (output != NULL) {
		if (output->type == nmsg_output_type_json)
			source_val = output->json->source;
		else if (output->type == nmsg_output_type_kafka_json)
			source_val = output->kafka->source;
	}

	if (source_val == 0 && np->has_source)
		source_val = np->source;

	if (source_val != 0) {
		sb_tmp_len = snprintf(sb_tmp, sizeof(sb_tmp), "%08x", source_val);
		declare_json_value(sb, "source", false);
		append_json_value_string(sb, sb_tmp, sb_tmp_len);
	}

	if (output != NULL) {
		if (output->type == nmsg_output_type_json)
			oper_val = output->json->operator;
		else if (output->type == nmsg_output_type_kafka_json)
			oper_val = output->kafka->operator;
	}

	if (oper_val == 0 && np->has_operator_)
		oper_val = np->operator_;

	if (oper_val != 0) {
		const char *operator = nmsg_alias_by_key(nmsg_alias_operator, oper_val);
		declare_json_value(sb, "operator", false);

		if (operator != NULL)
			append_json_value_string(sb, operator, strlen(operator));
		else
			append_json_value_int(sb, oper_val);
	}

	if (output != NULL) {
		if (output->type == nmsg_output_type_json)
			group_val = output->json->group;
		else if (output->type == nmsg_output_type_kafka_json)
			group_val = output->kafka->group;
	}

	if (group_val == 0 && np->has_group)
		group_val = np->group;

	if (group_val != 0) {
		const char *group = nmsg_alias_by_key(nmsg_alias_group, group_val);
		declare_json_value(sb, "group", false);

		if (group != NULL)
			append_json_value_string(sb, group, strlen(group));
		else
			append_json_value_int(sb, group_val);

	}

	declare_json_value(sb, "message", false);
	nmsg_strbuf_append_str(sb, "{", 1);

	for (size_t n = 0; n < msg->mod->n_fields; n++) {
		void *ptr;

		field = &msg->mod->plugin->fields[n];

		/* skip virtual fields unless they have a getter, in which
		 * case include the text for usability reasons */
		if (field->descr == NULL) {
			if (field->get != NULL) {
				unsigned val_idx = 0;

				for (;;) {
					ProtobufCBinaryData bdata;

					if (field->type == nmsg_msgmod_ft_ip ||
					    field->type == nmsg_msgmod_ft_bytes)
					{
						res = field->get(msg,
								 field,
								 val_idx,
								 (void **) &bdata.data,
								 &bdata.len,
								 msg->msg_clos);
						if (res != nmsg_res_success)
							break;
						ptr = &bdata;
					} else {
						res = field->get(msg,
								 field,
								 val_idx,
								 &ptr,
								 NULL,
								 msg->msg_clos);
						if (res != nmsg_res_success)
							break;
					}
					if (val_idx == 0) {
						declare_json_value(sb, field->name, (fidx++ == 0));

						if (field->flags & NMSG_MSGMOD_FIELD_REPEATED) {
							nmsg_strbuf_append_str(sb, "[", 1);
						}
					} else if (val_idx > 0 && (field->flags & NMSG_MSGMOD_FIELD_REPEATED))
							nmsg_strbuf_append_str(sb, ",", 1);

					res = _nmsg_message_payload_to_json_load(msg, field, ptr, sb);
					if (res != nmsg_res_success)
						goto err;
					val_idx += 1;

					if ((field->flags & NMSG_MSGMOD_FIELD_REPEATED) == 0)
						break;
				}

				if (val_idx > 0 && field->flags & NMSG_MSGMOD_FIELD_REPEATED) {
					nmsg_strbuf_append_str(sb, "]", 1);
				}
			}
			continue;
		}

		if (PBFIELD_ONE_PRESENT(m, field)) {
			declare_json_value(sb, field->name, (fidx++ == 0));
			ptr = PBFIELD(m, field, void);

			res = _nmsg_message_payload_to_json_load(msg, field, ptr, sb);
			if (res != nmsg_res_success)
				goto err;
		} else if (PBFIELD_REPEATED(field)) {
			declare_json_value(sb, field->name, (fidx++ == 0));
			nmsg_strbuf_append_str(sb, "[", 1);

			size_t n_entries = *PBFIELD_Q(m, field);
			for (size_t i = 0; i < n_entries; i++) {
				ptr = PBFIELD(m, field, void);
				char *array = *(char **) ptr;
				size_t siz = sizeof_elt_in_repeated_array(field->descr->type);

				res = _nmsg_message_payload_to_json_load(msg,
									 field,
									 &array[i * siz],
									 sb);
				if (res != nmsg_res_success)
					goto err;

				if (i < (n_entries - 1))
					nmsg_strbuf_append_str(sb, ",", 1);
			}

			nmsg_strbuf_append_str(sb, "]", 1);
		}
	}

	nmsg_strbuf_append_str(sb, "}}", 2);

	return (nmsg_res_success);

err:
	return (res);
}

static nmsg_res
_replace_invalid_utf8(struct nmsg_strbuf *sb, const unsigned char *s, size_t len)
{
	nmsg_res res;
	size_t begin, end;

	begin=end=0;

#define is_continuation(b)	((b&0xc0) == 0x80)
#define is_start2(b)		((b&0xe0) == 0xc0)
#define is_overlong2(b, c)	(b == 0xc0 || b == 0xc1)
#define is_start3(b)		((b&0xf0) == 0xe0)
#define is_overlong3(b,c)	(b == 0xe0 && c < 0xa0)
#define is_start4(b)		((b&0xf8) == 0xf0)
#define is_overlong4(b,c)	(b == 0xf0 && c < 0x90)
	while (end < len) {
		unsigned char ch = s[end];
		int skip = 1;

		if (ch < 0x80) {
			end++;
			continue;
		}

		if (is_start2(ch)) {
			if (((end+1) < len) &&
			    is_continuation(s[end+1]))
			{
				skip = 2;
				if (!is_overlong2(ch, s[end+1])) {
					end += skip;
					continue;
				}
			}
		}

		if (is_start3(ch)) {
			if (((end+2)<len) &&
			    is_continuation(s[end+1]) &&
			    is_continuation(s[end+2]))
			{
				skip = 3;
				if (!is_overlong3(ch,s[end+1])) {
					end += skip;
					continue;
				}
			}
		}

		if (is_start4(ch)) {
			if (((end+3)<len) &&
			    is_continuation(s[end+1]) &&
			    is_continuation(s[end+2]) &&
			    is_continuation(s[end+3]))
			{
				skip = 4;
				if (!is_overlong4(ch,s[end+1])) {
					end += skip;
					continue;
				}

			}
		}

		/* The string "\xef\xbf\xbd" is the UTF-8 encoding of
		 * the unicode replacement code point U+FFFD. We use
		 * this explicit encoding instead of "\ufffd" for its
		 * wider compiler support. 	*/
		res = nmsg_strbuf_append(sb, "%.*s\xef\xbf\xbd",
			end-begin, &s[begin]);
		if (res != nmsg_res_success)
			return res;
		end += skip;
		begin = end;
	}
#undef is_continuation
#undef is_start2
#undef is_start3
#undef is_overlong2
#undef is_overlong3

	if (end > begin)
		return nmsg_strbuf_append(sb, "%.*s", end-begin, &s[begin]);

	return (nmsg_res_success);
}

static unsigned
b64_encode_block(const char *txt_in, unsigned num_in, char *buf_out)
{
	static const char b64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const unsigned char *in_ptr = (const unsigned char*) txt_in;
	unsigned num_left = num_in;
	char *out_ptr = buf_out;
	unsigned u32;
	char nextc;
#define OUTPUT_BYTE(val)	nextc = b64char[(val) & 0x3f]; *out_ptr++ = nextc
	while (num_left >= 3) {
		u32 = *in_ptr++;
		u32 = (u32 << 8) | *in_ptr++;
		u32 = (u32 << 8) | *in_ptr++;
		OUTPUT_BYTE(u32 >> 18);
		OUTPUT_BYTE(u32 >> 12);
		OUTPUT_BYTE(u32 >>  6);
		OUTPUT_BYTE(u32);
		num_left -= 3;
	}

	if (num_left > 0) {
		u32 = *in_ptr++;
		if (num_left > 1)
			u32 = (u32 << 8) | *in_ptr++;
		else
			u32 <<= 8;
		u32 <<= 8;      /* Cannot be a third byte */
		OUTPUT_BYTE(u32 >> 18);
		OUTPUT_BYTE(u32 >> 12);
		if (num_left > 1) {
			OUTPUT_BYTE(u32 >> 6);
		} else
			*out_ptr++ = '=';
		*out_ptr++ = '=';
	}

	*out_ptr = '\0';

	return(out_ptr - buf_out);
}

nmsg_res
_nmsg_message_payload_to_json_load(struct nmsg_message *msg,
				   struct nmsg_msgmod_field *field, void *ptr,
				   void *gen)
{
	nmsg_res res = nmsg_res_success;
	ProtobufCBinaryData *bdata;
	struct nmsg_strbuf *g = (struct nmsg_strbuf *)gen;

	if (field->format != NULL) {
		char *endline = "";
		struct nmsg_strbuf_storage sbs;
		struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);

		if (field->type == nmsg_msgmod_ft_uint16 ||
		    field->type == nmsg_msgmod_ft_int16)
		{
			uint16_t val;
			uint32_t val32;
			memcpy(&val32, ptr, sizeof(uint32_t));
			val = (uint16_t) val32;
			res = field->format(msg, field, &val, sb, endline);
		} else {
			res = field->format(msg, field, ptr, sb, endline);
		}

		if (res == nmsg_res_success) {
			size_t len = nmsg_strbuf_len(sb);
			if (field->flags & NMSG_MSGMOD_FIELD_FORMAT_RAW) {
				nmsg_strbuf_append_str(g, sb->data, len);
			} else {
				append_json_value_string(g, sb->data, len);
			}
		} else {
			append_json_value_null(g);
		}

		_nmsg_strbuf_destroy(&sbs);

		return (res);
	}

	switch(field->type) {
	case nmsg_msgmod_ft_bytes: {
		size_t b64_str_len;
		struct nmsg_strbuf_storage b64_sbs;
		struct nmsg_strbuf *b64_sb = _nmsg_strbuf_init(&b64_sbs);

		bdata = (ProtobufCBinaryData *) ptr;
		if (bdata->data == NULL) {
			append_json_value_null(g);
			break;
		}

		_nmsg_strbuf_expand(b64_sb, 2 * bdata->len + 1);

		b64_str_len = b64_encode_block((const char *) bdata->data, bdata->len, b64_sb->data);
		append_json_value_string_noescape(g, b64_sb->data, b64_str_len);
		_nmsg_strbuf_destroy(&b64_sbs);
		break;
	}
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		struct nmsg_strbuf_storage sbs_tmp;
		struct nmsg_strbuf *sb_tmp = _nmsg_strbuf_init(&sbs_tmp);

		bdata = (ProtobufCBinaryData *) ptr;
		/* Treat (bdata->data == NULL) not as json null, but as an empty string. */

		res = _replace_invalid_utf8(sb_tmp,
					    (const unsigned char *) bdata->data,
					     bdata->len);
		if (res != nmsg_res_success) {
			_nmsg_strbuf_destroy(&sbs_tmp);
			return res;
		}
		append_json_value_string(g, sb_tmp->data, nmsg_strbuf_len(sb_tmp));
		_nmsg_strbuf_destroy(&sbs_tmp);
		break;
	}
	case nmsg_msgmod_ft_bool: {
		protobuf_c_boolean *b = (protobuf_c_boolean *) ptr;
		append_json_value_bool(g, *b);
		break;
	}
	case nmsg_msgmod_ft_enum: {
		ProtobufCEnumDescriptor *enum_descr;
		bool enum_found;
		unsigned enum_value;

		enum_found = false;
		enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;

		enum_value = *((unsigned *) ptr);
		for (unsigned i = 0; i < enum_descr->n_values; i++) {
			if ((unsigned) enum_descr->values[i].value == enum_value) {
				append_json_value_string_noescape(g, enum_descr->values[i].name, strlen(enum_descr->values[i].name));
				enum_found = true;
				break;
			}
		}
		if (enum_found == false) {
			append_json_value_int(g, enum_value);
		}
		break;
	}
	case nmsg_msgmod_ft_ip: {
		res = _nmsg_nmsg_mod_ip_to_string((ProtobufCBinaryData *) ptr, true, g);
		break;
	}
	case nmsg_msgmod_ft_uint16: {
		uint32_t val;
		memcpy(&val, ptr, sizeof(uint32_t));
		append_json_value_int(g, (uint16_t) val);
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		uint32_t val;
		memcpy(&val, ptr, sizeof(uint32_t));
		append_json_value_int(g, val);
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		uint64_t val;
		memcpy(&val, ptr, sizeof(uint64_t));
		append_json_value_int(g, val);
		break;
	}
	case nmsg_msgmod_ft_int16: {
		int32_t val;
		memcpy(&val, ptr, sizeof(int32_t));
		append_json_value_int(g, (int16_t)val);
		break;
	}
	case nmsg_msgmod_ft_int32: {
		int32_t val;
		memcpy(&val, ptr, sizeof(int32_t));
		append_json_value_int(g, val);
		break;
	}
	case nmsg_msgmod_ft_int64: {
		int64_t val;
		memcpy(&val, ptr, sizeof(int64_t));
		append_json_value_int(g, val);
		break;
	}
	case nmsg_msgmod_ft_double: {
		double val;
		memcpy(&val, ptr, sizeof(double));
		append_json_value_double(g, val);
		break;
	}
	default: {
		append_json_value_null(g);
		break;
	}
	} /* end switch */

	return (res);
}
