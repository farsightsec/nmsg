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
	struct nmsg_strbuf_storage sbs;
	struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);
	uint8_t * buf;
	size_t len;

	res = _nmsg_message_to_json(output, msg, sb);
	if (res != nmsg_res_success)
		goto out;

	len = nmsg_strbuf_len(sb);
	buf = (uint8_t *) _nmsg_strbuf_detach(sb);
	if (!buf) {
		res = nmsg_res_failure;
		goto out;
	}

	res = kafka_write(output->kafka->ctx, buf, len);

out:
	_nmsg_strbuf_destroy(&sbs);
	return res;
}
#else
nmsg_res
_output_kafka_json_write(nmsg_output_t output __attribute__((unused)),
						 nmsg_message_t msg __attribute__((unused))) {
	return (nmsg_res_notimpl);
}
#endif

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
