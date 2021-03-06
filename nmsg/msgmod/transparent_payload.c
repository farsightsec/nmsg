/*
 * Copyright (c) 2009-2016 by Farsight Security, Inc.
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

	if (field->format != NULL) {
		struct nmsg_strbuf *sb_tmp = NULL;
		nmsg_res res;

		sb_tmp = nmsg_strbuf_init();
		if (sb_tmp == NULL)
			return (nmsg_res_memfail);

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

		nmsg_strbuf_destroy(&sb_tmp);

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
	ProtobufCMessage *m;
	nmsg_res res;
	yajl_gen g = NULL;
	yajl_gen_status status;
	int yajl_rc;
	struct nmsg_strbuf *sb = NULL;
	struct nmsg_strbuf *sb_tmp = NULL;

	struct nmsg_msgmod_field *field;
	const char *vname, *mname;

	struct tm tm;
	time_t t;
	char when[32];

	/* unpack message */
	res = _nmsg_message_deserialize(msg);
	if (res != nmsg_res_success)
		return (res);
	m = msg->message;

	sb = nmsg_strbuf_init();
	if (sb == NULL)
		return (nmsg_res_memfail);

	sb_tmp = nmsg_strbuf_init();
	if (sb_tmp == NULL) {
		nmsg_strbuf_destroy(&sb);
		res = nmsg_res_memfail;
		goto err;
	}

	np = msg->np;

	g = yajl_gen_alloc(NULL);
	assert (g != NULL);

	yajl_rc = yajl_gen_config(g,
				  yajl_gen_print_callback,
				  callback_print_yajl_nmsg_strbuf,
				  sb);
	assert (yajl_rc != 0);

	yajl_rc = yajl_gen_config(g, yajl_gen_validate_utf8);
	assert (yajl_rc != 0);

	status = yajl_gen_map_open(g);
	assert(status == yajl_gen_status_ok);

	t = np->time_sec;
	gmtime_r(&t, &tm);
	strftime(when, sizeof(when), "%Y-%m-%d %T", &tm);

	nmsg_strbuf_reset(sb_tmp);
	nmsg_strbuf_append(sb_tmp, "%s.%09u", when, np->time_nsec);

	add_yajl_string(g, "time");
	status = yajl_gen_string(g, (unsigned char*) sb_tmp->data, nmsg_strbuf_len(sb_tmp));
	assert(status == yajl_gen_status_ok);

	vname = nmsg_msgmod_vid_to_vname(np->vid);
	if (vname == NULL)
		vname = "(unknown)";

	add_yajl_string(g, "vname");
	status = yajl_gen_string(g, (unsigned char *) vname, strlen(vname));
	assert(status == yajl_gen_status_ok);

	mname = nmsg_msgmod_msgtype_to_mname(np->vid, np->msgtype);
	if (mname == NULL)
		mname = "(unknown)";

	add_yajl_string(g, "mname");
	status = yajl_gen_string(g, (unsigned char *) mname, strlen(mname));
	assert(status == yajl_gen_status_ok);

	if (np->has_source) {
		nmsg_strbuf_reset(sb_tmp);
		nmsg_strbuf_append(sb_tmp, "%08x", np->source);
		add_yajl_string(g, "source");
		status = yajl_gen_string(g, (unsigned char *) sb_tmp->data, nmsg_strbuf_len(sb_tmp));
		assert(status == yajl_gen_status_ok);
	}

	if (np->has_operator_) {
		const char *operator = nmsg_alias_by_key(nmsg_alias_operator, np->operator_);
		add_yajl_string(g, "operator");
		if (operator != NULL) {
			status = yajl_gen_string(g, (unsigned char *) operator, strlen(operator));
		} else {
			status = yajl_gen_integer(g, np->operator_);
		}
		assert(status == yajl_gen_status_ok);
	}

	if (np->has_group) {
		const char *group = nmsg_alias_by_key(nmsg_alias_group, np->group);
		add_yajl_string(g, "group");
		if (group != NULL)
			status = yajl_gen_string(g, (unsigned char *) group, strlen(group));
		else
			status = yajl_gen_integer(g, np->group);
		assert(status == yajl_gen_status_ok);
	}

	add_yajl_string(g, "message");

	status = yajl_gen_map_open(g);
	assert(status == yajl_gen_status_ok);

	for (size_t n = 0; n < msg->mod->n_fields; n++) {
		void *ptr;

		field = &msg->mod->plugin->fields[n];

		/* skip virtual fields unless they have a getter, in which
		 * case include the text for usability reasons */
		if (field->descr == NULL) {
			if (field->get != NULL) {
				unsigned val_idx = 0;

				for (;;) {
					if (field->type == nmsg_msgmod_ft_ip ||
					    field->type == nmsg_msgmod_ft_bytes)
					{
						ProtobufCBinaryData bdata;
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
						status = yajl_gen_string(g,
							(unsigned char *) field->name,
							strlen(field->name));
						assert(status == yajl_gen_status_ok);

						if (field->flags & NMSG_MSGMOD_FIELD_REPEATED) {
							status = yajl_gen_array_open(g);
							assert(status == yajl_gen_status_ok);
						}
					}

					res = _nmsg_message_payload_to_json_load(msg,
										 field,
										 ptr,
										 g);
					if (res != nmsg_res_success)
						goto err;
					val_idx += 1;

					if ((field->flags & NMSG_MSGMOD_FIELD_REPEATED) == 0)
						break;
				}

				if (val_idx > 0 && field->flags & NMSG_MSGMOD_FIELD_REPEATED) {
					status = yajl_gen_array_close(g);
					assert(status == yajl_gen_status_ok);
				}
			}
			continue;
		}

		if (PBFIELD_ONE_PRESENT(m, field)) {
			status = yajl_gen_string(g,
						 (unsigned char *) field->name,
						 strlen(field->name));
			assert(status == yajl_gen_status_ok);

			ptr = PBFIELD(m, field, void);

			res = _nmsg_message_payload_to_json_load(msg, field, ptr, g);
			if (res != nmsg_res_success)
				goto err;
		} else if (PBFIELD_REPEATED(field)) {
			status = yajl_gen_string(g,
						 (unsigned char *) field->name,
						 strlen(field->name));
			assert(status == yajl_gen_status_ok);

			status = yajl_gen_array_open(g);
			assert(status == yajl_gen_status_ok);

			size_t n_entries = *PBFIELD_Q(m, field);
			for (size_t i = 0; i < n_entries; i++) {
				ptr = PBFIELD(m, field, void);
				char *array = *(char **) ptr;
				size_t siz = sizeof_elt_in_repeated_array(field->descr->type);

				res = _nmsg_message_payload_to_json_load(msg,
									 field,
									 &array[i * siz],
									 g);
				if (res != nmsg_res_success)
					goto err;
			}

			status = yajl_gen_array_close(g);
			assert(status == yajl_gen_status_ok);
		}
	}

	status = yajl_gen_map_close(g);
	assert(status == yajl_gen_status_ok);

	status = yajl_gen_map_close(g);
	assert(status == yajl_gen_status_ok);

	yajl_gen_reset(g, "");

	yajl_gen_free(g);

	*json = sb->data;
	free(sb);

	nmsg_strbuf_destroy(&sb_tmp);

	return (nmsg_res_success);

err:
	if (g != NULL)
		yajl_gen_free(g);

	nmsg_strbuf_destroy(&sb);
	nmsg_strbuf_destroy(&sb_tmp);

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

nmsg_res
_nmsg_message_payload_to_json_load(struct nmsg_message *msg,
				   struct nmsg_msgmod_field *field, void *ptr,
				   void *gen)
{
	ProtobufCBinaryData *bdata;

	yajl_gen g;
	yajl_gen_status status;

	g = (yajl_gen) gen;

	if (field->format != NULL) {
		struct nmsg_strbuf *sb = NULL;
		nmsg_res res;
		char *endline = "";

		sb = nmsg_strbuf_init();
		if (sb == NULL)
			return (nmsg_res_memfail);

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
			status = yajl_gen_string(g,
						 (const unsigned char *) sb->data,
						 nmsg_strbuf_len(sb));
			assert(status == yajl_gen_status_ok);
		} else {
			status = yajl_gen_null(g);
			assert(status == yajl_gen_status_ok);
		}

		nmsg_strbuf_destroy(&sb);

		return (nmsg_res_success);
	}

	switch(field->type) {
	case nmsg_msgmod_ft_bytes: {
		base64_encodestate b64;
		char *b64_str;
		size_t b64_str_len;

		base64_init_encodestate(&b64);
		bdata = (ProtobufCBinaryData *) ptr;
		b64_str = malloc(2 * bdata->len + 1);
		if (b64_str == NULL)
			return (nmsg_res_memfail);

		b64_str_len = base64_encode_block((const char *) bdata->data,
						  bdata->len,
						  b64_str,
						  &b64);
		b64_str_len += base64_encode_blockend(b64_str + b64_str_len, &b64);
		status = yajl_gen_string(g, (const unsigned char *) b64_str, b64_str_len);
		free(b64_str);
		assert(status == yajl_gen_status_ok);
		break;
	}
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		struct nmsg_strbuf *sb_tmp;
		nmsg_res res;

		bdata = (ProtobufCBinaryData *) ptr;
		sb_tmp = nmsg_strbuf_init();
		if (sb_tmp == NULL)
			return (nmsg_res_memfail);
		res = _replace_invalid_utf8(sb_tmp,
					    (const unsigned char *) bdata->data,
					     bdata->len);
		if (res != nmsg_res_success) {
			nmsg_strbuf_destroy(&sb_tmp);
			return res;
		}
		status = yajl_gen_string(g,
					(const unsigned char *)sb_tmp->data,
					nmsg_strbuf_len(sb_tmp));
		assert(status == yajl_gen_status_ok);
		nmsg_strbuf_destroy(&sb_tmp);
		break;
	}
	case nmsg_msgmod_ft_bool: {
		protobuf_c_boolean *b = (protobuf_c_boolean *) ptr;
		status = yajl_gen_bool(g, *b);
		assert(status == yajl_gen_status_ok);
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
				status = yajl_gen_string(g,
					(unsigned char *) enum_descr->values[i].name,
					strlen(enum_descr->values[i].name));
				assert(status == yajl_gen_status_ok);
				enum_found = true;
				break;
			}
		}
		if (enum_found == false) {
			status = yajl_gen_integer(g, enum_value);
			assert(status == yajl_gen_status_ok);
		}
		break;
	}
	case nmsg_msgmod_ft_ip: {
		char sip[INET6_ADDRSTRLEN];
		int family = 0;

		bdata = (ProtobufCBinaryData *) ptr;

		if (bdata->len == 4) {
			family = AF_INET;
		} else if (bdata->len == 16) {
			family = AF_INET6;
		}

		if (family && inet_ntop(family, bdata->data, sip, sizeof(sip))) {
			status = yajl_gen_string(g, (const unsigned char *) sip, strlen(sip));
			assert(status == yajl_gen_status_ok);
		} else {
			status = yajl_gen_null(g);
			assert(status == yajl_gen_status_ok);
		}
		break;
	}
	case nmsg_msgmod_ft_uint16: {
		uint32_t val;
		memcpy(&val, ptr, sizeof(uint32_t));
		status = yajl_gen_integer(g, (uint16_t) val);
		assert(status == yajl_gen_status_ok);
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		uint32_t val;
		memcpy(&val, ptr, sizeof(uint32_t));
		status = yajl_gen_integer(g, val);
		assert(status == yajl_gen_status_ok);
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		uint64_t val;
		struct nmsg_strbuf *sb = NULL;

		sb = nmsg_strbuf_init();
		if (sb == NULL)
			return (nmsg_res_memfail);

		memcpy(&val, ptr, sizeof(uint64_t));
		nmsg_strbuf_append(sb, "%" PRIu64, val);

		status = yajl_gen_number(g, (const char *) sb->data, nmsg_strbuf_len(sb));
		assert(status == yajl_gen_status_ok);

		nmsg_strbuf_destroy(&sb);

		break;
	}
	case nmsg_msgmod_ft_int16: {
		int32_t val;
		memcpy(&val, ptr, sizeof(int32_t));
		status = yajl_gen_integer(g, (int16_t) val);
		assert(status == yajl_gen_status_ok);
		break;
	}
	case nmsg_msgmod_ft_int32: {
		int32_t val;
		memcpy(&val, ptr, sizeof(int32_t));
		status = yajl_gen_integer(g, val);
		assert(status == yajl_gen_status_ok);
		break;
	}
	case nmsg_msgmod_ft_int64: {
		int64_t val;
		memcpy(&val, ptr, sizeof(int64_t));
		status = yajl_gen_integer(g, val);
		assert(status == yajl_gen_status_ok);
		break;
	}
	case nmsg_msgmod_ft_double: {
		double val;
		memcpy(&val, ptr, sizeof(double));
		status = yajl_gen_double(g, val);
		assert(status == yajl_gen_status_ok);
		break;
	}
	default: {
		status = yajl_gen_null(g);
		assert(status == yajl_gen_status_ok);
		break;
	}
	} /* end switch */

	return (nmsg_res_success);
}
#else /* HAVE_YAJL */
nmsg_res
_nmsg_message_payload_to_json(__attribute__((unused)) struct nmsg_message *msg,
			      __attribute__((unused)) char **pres) {
	return (nmsg_res_notimpl);
}

nmsg_res
_nmsg_message_payload_to_json_load(__attribute__((unused)) struct nmsg_message *msg,
				   __attribute__((unused)) struct nmsg_msgmod_field *field,
				   __attribute__((unused)) void *ptr,
				   __attribute__((unused)) void *gen)
{
	return (nmsg_res_notimpl);
}
#endif /* HAVE_YAJL */
