/*
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
	char *json_data;

	/* lock output */
	pthread_mutex_lock(&output->json->lock);

	res = nmsg_message_to_json(msg, &json_data);
	if (res != nmsg_res_success)
		goto out;

	fprintf(output->pres->fp, "%s\n", json_data);
	if (output->pres->flush)
		fflush(output->pres->fp);
	free(json_data);

out:
	/* unlock output */
	pthread_mutex_unlock(&output->json->lock);

	return (nmsg_res_success);
}
