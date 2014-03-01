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
#ifdef HAVE_MSGPACK
#include <msgpack.h>
#include <inttypes.h>
#include <string.h>
#endif
#ifdef HAVE_LIBXML2
#include <libxml/parser.h>
#endif

#include "encode.pb-c.h"

#define CHECK(res) { if ((res != nmsg_res_success)) return (res); }

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

// Ported to nmsg_strbuf from msgpack-c:src/objectc.c:msgpack_object_print 0.5.8
static nmsg_res msgpack_obj2sb(struct nmsg_strbuf * out, msgpack_object o)
{
	switch(o.type) {
	case MSGPACK_OBJECT_NIL:
		CHECK(nmsg_strbuf_append(out, "nil"));
		break;

	case MSGPACK_OBJECT_BOOLEAN:
		CHECK(nmsg_strbuf_append(out, (o.via.boolean ? "true" : "false")));
		break;

	case MSGPACK_OBJECT_POSITIVE_INTEGER:
		CHECK(nmsg_strbuf_append(out, "%"PRIu64, o.via.u64));
		break;

	case MSGPACK_OBJECT_NEGATIVE_INTEGER:
		CHECK(nmsg_strbuf_append(out, "%"PRIi64, o.via.i64));
		break;

	case MSGPACK_OBJECT_DOUBLE:
		CHECK(nmsg_strbuf_append(out, "%f", o.via.dec));
		break;

	case MSGPACK_OBJECT_RAW: {
			nmsg_res res;
			char * buf = malloc(o.via.raw.size+1);

			if (!buf) {
				return (nmsg_res_memfail);
			}

			bcopy(o.via.raw.ptr, buf, o.via.raw.size);
			buf[o.via.raw.size] = 0;
			if (strlen(buf) == o.via.raw.size) {
				res = nmsg_strbuf_append(out, "\"%s\"", buf);
			} else {
				res = nmsg_strbuf_append(out, "\"%s<truncated>\"", buf);
			}
			free (buf);
			CHECK(res);
			break;
		}
	case MSGPACK_OBJECT_ARRAY:
		CHECK(nmsg_strbuf_append(out, "["));
		if(o.via.array.size != 0) {
			msgpack_object* p = o.via.array.ptr;
			CHECK(msgpack_obj2sb(out, *p));
			++p;
			msgpack_object* const pend = o.via.array.ptr + o.via.array.size;
			for(; p < pend; ++p) {
				CHECK(nmsg_strbuf_append(out, ", "));
				CHECK(msgpack_obj2sb(out, *p));
			}
		}
		CHECK(nmsg_strbuf_append(out, "]"));
		break;

	case MSGPACK_OBJECT_MAP:
		CHECK(nmsg_strbuf_append(out, "{"));
		if(o.via.map.size != 0) {
			msgpack_object_kv* p = o.via.map.ptr;
			CHECK(msgpack_obj2sb(out, p->key));
			CHECK(nmsg_strbuf_append(out, "=>"));
			CHECK(msgpack_obj2sb(out, p->val));
			++p;
			msgpack_object_kv* const pend = o.via.map.ptr + o.via.map.size;
			for(; p < pend; ++p) {
				CHECK(nmsg_strbuf_append(out, ", "));
				CHECK(msgpack_obj2sb(out, p->key));
				CHECK(nmsg_strbuf_append(out, "=>"));
				CHECK(msgpack_obj2sb(out, p->val));
			}
		}
		CHECK(nmsg_strbuf_append(out, "}"));
		break;

	default:
		// FIXME
		CHECK(nmsg_strbuf_append(out, "#<UNKNOWN %i %"PRIu64">", o.type, o.via.u64));
	}

	return (nmsg_res_success);
}

static nmsg_res
msgpack_print(ProtobufCBinaryData *payload, struct nmsg_msgmod_field *field, struct nmsg_strbuf *sb, const char *endline) {
	nmsg_res res;
#ifdef HAVE_MSGPACK
	struct nmsg_strbuf * buf = nmsg_strbuf_init();

	if (!buf) {
		return (nmsg_res_memfail);
	}

	msgpack_unpacked msg;
	msgpack_unpacked_init(&msg);

	if (!msgpack_unpack_next(&msg, (char*)payload->data, payload->len, 0)) {
		res = nmsg_res_failure;
		goto cleanup;
	}

	res = msgpack_obj2sb(buf, msg.data);
	if (res != nmsg_res_success) {
		goto cleanup;
	}

	res = nmsg_strbuf_append(sb, "%s: %s%s", field->name, buf->data, endline);

cleanup:
	msgpack_unpacked_destroy(&msg);
	nmsg_strbuf_destroy(&buf);
	return res;
#else
	res = nmsg_strbuf_append(sb, "%s: <MSGPACK>%s", field->name, endline);
	return res;
#endif
}

static void xml_generic_error_noop(void * ctx, const char * msg, ...) {
	nmsg_res * res = ctx;
	*res = nmsg_res_failure;
}

static void xml_structured_error_noop(void * ctx, xmlErrorPtr error) {
	nmsg_res * res = ctx;
	*res = nmsg_res_failure;
}

static nmsg_res
xml_print(ProtobufCBinaryData *payload, struct nmsg_msgmod_field *field, struct nmsg_strbuf *sb, const char *endline) {
	nmsg_res res = nmsg_res_success;
#ifdef HAVE_LIBXML2
	xmlDocPtr doc;
	xmlChar *xmlbuff;
	int buffersize;

	xmlSetGenericErrorFunc(&res, xml_generic_error_noop);
	xmlSetStructuredErrorFunc(&res, xml_structured_error_noop);
	doc = xmlReadMemory((char*)payload->data, payload->len, NULL, NULL, 0);
	if (!doc) {
		return (nmsg_res_failure);
	}
	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
	if (res) {
		goto cleanup;
	}

	res = nmsg_strbuf_append(sb, "%s:%s%s", field->name, endline, (char*)xmlbuff);

cleanup:
	xmlFree(xmlbuff);
	xmlFreeDoc(doc);

	return res;
#else
	res = nmsg_strbuf_append(sb, "%s: <XML>%s", field->name, endline);
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
			return msgpack_print(payload, field, sb, endline);
		case NMSG__BASE__ENCODE_TYPE__XML:
			return xml_print(payload, field, sb, endline);
		default:
			return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}
