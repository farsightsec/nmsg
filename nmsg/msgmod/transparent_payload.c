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

	if (field->format != NULL) {
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
	nmsg_strbuf_append_str(sb, str, len);
}

static
void num_to_str(int num, int size, char * ptr) {
	int ndx = size - 1;

	while(size > 0) {
		int digit = num % 10;
		ptr[ndx] = '0' + digit;
		--ndx;
		--size;
		num /= 10;
	}
}

nmsg_res
_nmsg_message_payload_to_json(struct nmsg_message *msg, struct nmsg_strbuf *sb) {
	Nmsg__NmsgPayload *np;
	ProtobufCMessage *m;
	nmsg_res res;
	yajl_gen g = NULL;
	yajl_gen_status status;
	int yajl_rc;
	char sb_tmp[256];
	size_t sb_tmp_len;

	struct nmsg_msgmod_field *field;
	const char *vname, *mname;

	struct tm tm;
	time_t t;
	char when[]="XXXX-XX-XX XX:XX:XX.XXXXXXXXX";

	/* unpack message */
	res = _nmsg_message_deserialize(msg);
	if (res != nmsg_res_success)
		return (res);
	m = msg->message;

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

	num_to_str(1900 + tm.tm_year, 4, when);
	num_to_str(1 + tm.tm_mon, 2, when + 5);
	num_to_str(tm.tm_mday, 2, when + 8);
	num_to_str(tm.tm_hour, 2, when + 11);
	num_to_str(tm.tm_min, 2, when + 14);
	num_to_str(tm.tm_sec, 2, when + 17);
	num_to_str(np->time_nsec, 9, when + 20);

	add_yajl_string(g, "time");
	status = yajl_gen_string(g, (unsigned char *) when, sizeof(when) - 1);
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
		sb_tmp_len = snprintf(sb_tmp, sizeof(sb_tmp), "%08x", np->source);
		add_yajl_string(g, "source");
		status = yajl_gen_string(g, (unsigned char *) sb_tmp, sb_tmp_len);
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

	return (nmsg_res_success);

err:
	if (g != NULL)
		yajl_gen_free(g);

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
		nmsg_res res;
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
			status = yajl_gen_string(g,
						 (const unsigned char *) sb->data,
						 nmsg_strbuf_len(sb));
			assert(status == yajl_gen_status_ok);
		} else {
			status = yajl_gen_null(g);
			assert(status == yajl_gen_status_ok);
		}

		_nmsg_strbuf_destroy(&sbs);

		return (nmsg_res_success);
	}

	switch(field->type) {
	case nmsg_msgmod_ft_bytes: {
		base64_encodestate b64;
		size_t b64_str_len;
		nmsg_res res;
		struct nmsg_strbuf_storage b64_sbs;
		struct nmsg_strbuf *b64_sb = _nmsg_strbuf_init(&b64_sbs);

		base64_init_encodestate(&b64);
		bdata = (ProtobufCBinaryData *) ptr;

		res = _nmsg_strbuf_expand(b64_sb, 2 * bdata->len + 1);
		if (res != nmsg_res_success)
			return (nmsg_res_memfail);

		b64_str_len = base64_encode_block((const char *) bdata->data,
						  bdata->len,
						  b64_sb->data,
						  &b64);
		b64_str_len += base64_encode_blockend(b64_sb->data + b64_str_len, &b64);
		status = yajl_gen_string(g, (const unsigned char *) b64_sb->data, b64_str_len);
		_nmsg_strbuf_destroy(&b64_sbs);
		assert(status == yajl_gen_status_ok);
		break;
	}
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		nmsg_res res;
		struct nmsg_strbuf_storage sbs_tmp;
		struct nmsg_strbuf *sb_tmp = _nmsg_strbuf_init(&sbs_tmp);

		bdata = (ProtobufCBinaryData *) ptr;

		res = _replace_invalid_utf8(sb_tmp,
					    (const unsigned char *) bdata->data,
					     bdata->len);
		if (res != nmsg_res_success) {
			_nmsg_strbuf_destroy(&sbs_tmp);
			return res;
		}
		status = yajl_gen_string(g,
					(const unsigned char *)sb_tmp->data,
					nmsg_strbuf_len(sb_tmp));
		assert(status == yajl_gen_status_ok);
		_nmsg_strbuf_destroy(&sbs_tmp);
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
		struct nmsg_strbuf_storage sbs;
		struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);

		memcpy(&val, ptr, sizeof(uint64_t));
		nmsg_strbuf_append(sb, "%" PRIu64, val);

		status = yajl_gen_number(g, (const char *) sb->data, nmsg_strbuf_len(sb));
		assert(status == yajl_gen_status_ok);

		_nmsg_strbuf_destroy(&sbs);
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
			      __attribute__((unused)) struct nmsg_strbuf *pres) {
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
