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

/* Import. */

#include "private.h"

/* Internal functions. */

#ifdef HAVE_YAJL
nmsg_res
_input_json_read(nmsg_input_t input, nmsg_message_t *msg) {
	char line[1024];
	nmsg_res res;
	struct nmsg_strbuf *sb;

	sb = nmsg_strbuf_init();
	if (sb == NULL)
		return (nmsg_res_memfail);

	while (fgets(line, sizeof(line), input->json->fp) != NULL) {
		nmsg_strbuf_append(sb, "%s", line);

		if (sb->pos - sb->data == 0 || sb->pos[-1] != '\n') {
			continue;
		}
		if (sb->pos - sb->data == 1) {
			nmsg_strbuf_reset(sb);
			continue;
		}

		res = nmsg_message_from_json(sb->data, msg);

		nmsg_strbuf_destroy(&sb);

		return (res);
	}

	nmsg_strbuf_destroy(&sb);
	return (nmsg_res_eof);
}
#else /* HAVE_YAJL */
nmsg_res
_input_json_read(nmsg_input_t input, nmsg_message_t *msg) {
	return (nmsg_res_notimpl);
}
#endif /* HAVE_YAJL */
