/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2015 by Farsight Security, Inc.
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

#ifdef HAVE_LIBRDKAFKA
nmsg_res
_output_kafka_json_write(nmsg_output_t output, nmsg_message_t msg) {
	nmsg_res res;
	struct nmsg_strbuf_storage sbs, key_sbs;
	struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);
	struct nmsg_strbuf *key_sb = NULL;
	uint8_t *buf, *key = NULL;
	size_t len, key_len = 0;

	res = _nmsg_message_to_json(output, msg, sb);
	if (res != nmsg_res_success)
		goto out;

	if (output->kafka->key_field != NULL) {
		key_sb = _nmsg_strbuf_init(&key_sbs);
		res = _nmsg_message_get_field_value_as_key(msg, output->kafka->key_field, key_sb);

		if (res != nmsg_res_success)
			goto out;

		key_len = nmsg_strbuf_len(key_sb);
		key = (uint8_t *) key_sb->data;
	}

	len = nmsg_strbuf_len(sb);
	buf = (uint8_t *) _nmsg_strbuf_detach(sb);
	if (!buf) {
		res = nmsg_res_failure;
		goto out;
	}

	res = kafka_write(output->kafka->ctx, key, key_len, buf, len);

out:
	if (key_sb != NULL)
		_nmsg_strbuf_destroy(&key_sbs);

	_nmsg_strbuf_destroy(&sbs);
	return res;
}

nmsg_res
_output_kafka_json_flush(nmsg_output_t output) {
	kafka_flush(output->kafka->ctx);
	return nmsg_res_success;
}
#endif /* HAVE_LIBRDKAFKA */

nmsg_res
_output_json_write(nmsg_output_t output, nmsg_message_t msg) {
	nmsg_res res;
	struct nmsg_strbuf_storage sbs;
	struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);

	res = _nmsg_message_to_json(output, msg, sb);
	if (res != nmsg_res_success)
		goto out;

	/* lock output */
	pthread_mutex_lock(&output->json->lock);

	fputs(sb->data, output->json->fp);
	fputc('\n', output->json->fp);

	if (output->json->flush)
		fflush(output->json->fp);

	/* unlock output */
	pthread_mutex_unlock(&output->json->lock);

out:
	_nmsg_strbuf_destroy(&sbs);
	return res;
}
