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

			array_v = yajl_tree_get(message_v, field_path, yajl_t_array);
			for (v = 0; v < YAJL_GET_ARRAY(array_v)->len; v++) {
				field_v = YAJL_GET_ARRAY(array_v)->values[v];
				//res = nmsg_message_set_field_by_idx(*msg, n, v, /* data */ 0, /* len */ 0);
				if (res != nmsg_res_success) {
					return (res);
				}
			}
		} else {
			field_v = yajl_tree_get(message_v, field_path, yajl_t_any);
			//res = nmsg_message_set_field_by_idx(*msg, n, 0, /* data */ 0, /* len */ 0);
			if (res != nmsg_res_success) {
				return (res);
			}
		}
	}

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_json_to_payload_load(struct nmsg_msgmod_field *field,
				  struct nmsg_msgmod_clos *clos,
				  const char *value, void *ptr, int *qptr)
{
	return (nmsg_res_notimpl);
}

#else /* HAVE_YAJL */
nmsg_res
_nmsg_msgmod_json_to_message(void * val, struct nmsg_message *msg) {
	return (nmsg_res_notimpl);
}

nmsg_res
_nmsg_msgmod_json_to_payload_load(struct nmsg_msgmod_field *field,
				  struct nmsg_msgmod_clos *clos,
				  const char *value, void *ptr, int *qptr)
{
	return (nmsg_res_notimpl);
}
#endif /* HAVE_YAJL */
