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
			break;
		case NMSG__BASE__ENCODE_TYPE__YAML:
			break;
		case NMSG__BASE__ENCODE_TYPE__MSGPACK:
			break;
		case NMSG__BASE__ENCODE_TYPE__XML:
			break;
		default:
			return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}
