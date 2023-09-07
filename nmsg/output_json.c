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

nmsg_res
_output_json_write(nmsg_output_t output, nmsg_message_t msg) {
	nmsg_res res;
	struct nmsg_strbuf_storage sbs;
	struct nmsg_strbuf *sb = _nmsg_strbuf_init(&sbs);

	res = _nmsg_message_to_json(msg, sb);
	if (res != nmsg_res_success)
		goto out;

	/* lock output */
	pthread_mutex_lock(&output->json->lock);

	fputs(sb->data, output->pres->fp);
	fputc('\n', output->pres->fp);

	if (output->pres->flush)
		fflush(output->pres->fp);

	/* unlock output */
	pthread_mutex_unlock(&output->json->lock);

out:
	_nmsg_strbuf_destroy(&sbs);
	return res;
}
