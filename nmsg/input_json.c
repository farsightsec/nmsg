/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2015, 2019 by Farsight Security, Inc.
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

#if (defined HAVE_JSON_C) && (defined HAVE_LIBRDKAFKA)
nmsg_res
_input_kafka_json_read(nmsg_input_t input, nmsg_message_t *msg) {
	nmsg_res res;
	char *buf;
	size_t buf_len;

	res = kafka_read_start(input->kafka->ctx, (uint8_t **) &buf, &buf_len);
	if (res != nmsg_res_success)
		return res;

	if (buf_len == 0)
		return nmsg_res_failure;

	res = nmsg_message_from_json((const char*) buf, msg);

	if (res == nmsg_res_parse_error && nmsg_get_debug() >= 2)
		fprintf(stderr, "Kafka JSON parse error: \"%s\"\n", buf);

	kafka_read_close(input->kafka->ctx);
	return res;
}
#else /* (defined HAVE_JSON_C) && (defined HAVE_LIBRDKAFKA) */
nmsg_res
_input_kafka_json_read(nmsg_input_t input __attribute__((unused)),
					   nmsg_message_t *msg __attribute__((unused))) {
	return (nmsg_res_notimpl);
}
#endif /* (defined HAVE_JSON_C) && (defined HAVE_LIBRDKAFKA) */

#ifdef HAVE_JSON_C
nmsg_res
_input_json_read(nmsg_input_t input, nmsg_message_t *msg) {
	char line[1024];
	nmsg_res res;
	struct nmsg_strbuf_storage sbs;
	struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);

	while (fgets(line, sizeof(line), input->json->fp) != NULL) {
		res = nmsg_strbuf_append_str(sb, line, strlen(line));
		if (res != nmsg_res_success)
			return (res);

		if (sb->pos - sb->data == 0 || sb->pos[-1] != '\n') {
			continue;
		}
		if (sb->pos - sb->data == 1) {
			nmsg_strbuf_reset(sb);
			continue;
		}

		res = nmsg_message_from_json(sb->data, msg);

		/* skip failed messages */
		if (res == nmsg_res_parse_error) {
			if (nmsg_get_debug() >= 2) {
				sb->pos[-1] = 0;
				fprintf(stderr, "JSON parse error: \"%s\"\n", sb->data);
			}
			nmsg_strbuf_reset(sb);
			continue;
		}

		_nmsg_strbuf_destroy(&sbs);

		return (res);
	}

	_nmsg_strbuf_destroy(&sbs);
	return (nmsg_res_eof);
}
#else /* HAVE_JSON_C */
nmsg_res
_input_json_read(__attribute__((unused)) nmsg_input_t input,
                 __attribute__((unused)) nmsg_message_t *msg) {
	return (nmsg_res_notimpl);
}
#endif /* HAVE_JSON_C */
