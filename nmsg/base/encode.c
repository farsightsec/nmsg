/* encode nmsg message module */

/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2011 by Farsight Security, Inc.
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

/* Import. */
#ifdef HAVE_JSON_C
#include <json.h>
#endif

#include "encode.pb-c.h"

#include "libmy/b64_encode.h"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_FORMATTER(encode_payload_format);

/* Data. */

struct nmsg_msgmod_field encode_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "payload",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED | NMSG_MSGMOD_FIELD_FORMAT_RAW,
		.format = encode_payload_format
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_BASE,
	.msgtype	= { NMSG_VENDOR_BASE_ENCODE_ID, NMSG_VENDOR_BASE_ENCODE_NAME },

	.pbdescr	= &nmsg__base__encode__descriptor,
	.fields		= encode_fields
};


static bool
encode_payload_add_value(struct nmsg_strbuf *sb, int type_value, const char *data, size_t len)
{
	bool is_json = (type_value == NMSG__BASE__ENCODE__ENCODE_TYPE__JSON);

	/* validate json */
	if (is_json) {
#ifdef HAVE_JSON_C
		struct json_tokener *jtok = json_tokener_new();
		struct json_object *jobj;

		if (jtok == NULL)
			return false;

		jobj = json_tokener_parse_ex(jtok, data, len);

		json_object_put(jobj);
		json_tokener_free(jtok);
		if (jobj == NULL)
			return false;
#else
        return false;
#endif
	}

	declare_json_value(sb, "val", true);

	if (is_json) {
		nmsg_strbuf_append_str(sb, (const char *) data, len);
	} else {
		append_json_value_string(sb, (const char *) data, len);
	}

	return true;
}

static nmsg_res
encode_payload_format(nmsg_message_t msg,
		      struct nmsg_msgmod_field *field,
		      void *ptr,
		      struct nmsg_strbuf *sb,
		      const char *endline)
{
	ProtobufCBinaryData *bdata = (ProtobufCBinaryData *) ptr;
	base64_encodestate b64;
	const char *type_field = "type";
	unsigned int *type_value;
	char *b64_buffer, *b64_ptr;
	size_t len;
	bool no_value = true;

	nmsg_res res = nmsg_message_get_field(msg, type_field, 0, (void **) &type_value, &len);
	if (res != nmsg_res_success)
		return (res);

	if (type_value == NULL)
		return (nmsg_res_failure);

	nmsg_strbuf_append_str(sb, "{", 1);

	if (*type_value != NMSG__BASE__ENCODE__ENCODE_TYPE__MSGPACK)
		no_value = !encode_payload_add_value(sb, *type_value, (const char *) bdata->data, bdata->len);

	declare_json_value(sb, "b64", no_value);

	base64_init_encodestate(&b64);
	b64_buffer = alloca(2 * bdata->len + 1);
	assert(b64_buffer != NULL);

	b64_ptr = b64_buffer + base64_encode_block((const char *) bdata->data, bdata->len, b64_buffer, &b64);
	b64_ptr += base64_encode_blockend(b64_ptr, &b64);

	append_json_value_string(sb, (const char *) b64_buffer, b64_ptr - b64_buffer);

	nmsg_strbuf_append_str(sb, "}", 1);
	return (nmsg_res_success);
}
