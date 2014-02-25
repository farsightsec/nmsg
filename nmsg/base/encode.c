/* encode nmsg message module */

/*
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

#ifdef HAVE_JANSSON
#include <jansson.h>
#endif
#ifdef HAVE_YAML
#include <yaml.h>
#endif

#include "encode.pb-c.h"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_PRINTER(payload_print);

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
		.flags = NMSG_MSGMOD_FIELD_REQUIRED,
		.print = payload_print
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

static nmsg_res
json_print(ProtobufCBinaryData *payload, struct nmsg_msgmod_field *field, struct nmsg_strbuf *sb, const char *endline) {
	nmsg_res res;
#ifdef HAVE_JANSSON
	json_t * json;
	json_error_t error;
	char * buf;

	json = json_loadb((const char *)payload->data, payload->len, 0, &error);
	if (! json) {
		return (nmsg_res_failure);
	}
	buf = json_dumps(json, JSON_ENSURE_ASCII);

	res = nmsg_strbuf_append(sb, "%s: %s%s", field->name, buf, endline);

	free (buf);
	json_decref(json);

	return res;
#else
	res = nmsg_strbuf_append(sb, "%s: <JSON>%s", field->name, endline);
	return res;
#endif
}

// Sets *ext to a pointer that must be freed by the caller.
static int yaml_emit_to_ptr(void * ext, unsigned char * buffer, size_t size) {
	char ** hdl = (char**)ext;
	char * end;
	*hdl = malloc(size+1);
	if (!*hdl) {
		return 0;
	}

	bcopy(buffer, *hdl, size);
	*hdl[size] = 0;

	// Strip off line breaks at the end
	end = *hdl+size-1;
	while (end >= *hdl && *end == '\n') {
		*end = 0;
		end--;
	}
	return 1;
}

static nmsg_res
yaml_print(ProtobufCBinaryData *payload, struct nmsg_msgmod_field *field, struct nmsg_strbuf *sb, const char *endline) {
	nmsg_res res;
#ifdef HAVE_YAML
	yaml_parser_t parser;
	yaml_document_t document;
	yaml_emitter_t emitter;

	char * buf = 0;

	if (!yaml_parser_initialize(&parser)) {
		return (nmsg_res_failure);
	}
	if (!yaml_emitter_initialize(&emitter)) {
		goto error;
	}

	yaml_parser_set_input_string(&parser, (unsigned char *)payload->data, payload->len);
	if (!yaml_parser_load(&parser, &document)) {
		goto error2;
	}

	yaml_emitter_set_output(&emitter, yaml_emit_to_ptr, &buf);
	if (!yaml_emitter_open(&emitter)) {
		goto error3;
	}
	if (!yaml_emitter_dump(&emitter, &document)) {
		goto error2;
	}

	yaml_emitter_close(&emitter);
	yaml_emitter_delete(&emitter);
	// yaml_emitter_dump deleted document
	yaml_parser_delete(&parser);

	res = nmsg_strbuf_append(sb, "%s:%s%s%s", field->name, endline, buf, endline);
	free (buf);

	return res;
error3:
	yaml_document_delete(&document);
error2:
	yaml_emitter_delete(&emitter);
error:
	yaml_parser_delete(&parser);
	return (nmsg_res_failure);
#else
	res = nmsg_strbuf_append(sb, "%s: <YAML>%s", field->name, endline);
	return res;
#endif
}

static nmsg_res
payload_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		void * ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	nmsg_res res;
	uint32_t *type;
	ProtobufCBinaryData *payload = ptr;
	size_t len;

	res = nmsg_message_get_field(msg, "type", 0, (void**) &type, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	switch (*type) {
		case NMSG__BASE__ENCODE_TYPE__TEXT: {
			char * buf;
			buf = alloca(payload->len+1);
			if (!buf) {
				return (nmsg_res_failure);
			}
			bcopy(payload->data, buf, payload->len);
			buf[payload->len] = 0;

			res = nmsg_strbuf_append(sb, "%s: %s%s", field->name, buf, endline);
			return res;
		}
		case NMSG__BASE__ENCODE_TYPE__JSON:
			return json_print(payload, field, sb, endline);
		case NMSG__BASE__ENCODE_TYPE__YAML: 
			return yaml_print(payload, field, sb, endline);
		case NMSG__BASE__ENCODE_TYPE__MSGPACK:
			break;
		case NMSG__BASE__ENCODE_TYPE__XML:
			break;
		default:
			return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}
