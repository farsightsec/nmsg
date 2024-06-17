/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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
_input_nmsg_read_null(nmsg_input_t input	__attribute__((unused)),
		      nmsg_message_t *msg	__attribute__((unused)))
{
	return (nmsg_res_failure);
}

nmsg_res
_input_nmsg_loop_null(nmsg_input_t input	__attribute__((unused)),
		      int cnt			__attribute__((unused)),
		      nmsg_cb_message cb	__attribute__((unused)),
		      void *user		__attribute__((unused)))
{
	return (nmsg_res_failure);
}

/* Export. */

nmsg_res
nmsg_input_read_null(nmsg_input_t input, uint8_t *buf, size_t buf_len,
		     struct timespec *ts, nmsg_message_t **msgarray, size_t *n_msg)
{
	nmsg_res res;
	ssize_t msgsize;

	assert(input->stream->type == nmsg_stream_type_null);

	/* use caller-supplied time, else retrieve the current time */
	if (ts != NULL)
		memcpy(&input->stream->now, ts, sizeof(*ts));
	else
		nmsg_timespec_get(&input->stream->now);

	/* deserialize the NMSG header */
	res = _input_nmsg_deserialize_header(buf, buf_len, &msgsize, &input->stream->flags);
	if (res != nmsg_res_success)
		return (res);
	buf += NMSG_HDRLSZ_V2;

	/* the entire NMSG container must be present */
	if ((size_t) msgsize != buf_len - NMSG_HDRLSZ_V2)
		return (nmsg_res_parse_error);

	/* unpack message container */
	res = _input_nmsg_unpack_container(input, &input->stream->nmsg, buf, msgsize);

	/* expire old outstanding fragments */
	_input_frag_gc(input->stream);

	/* convert NMSG payloads to nmsg_message_t objects */
	if (input->stream->nmsg != NULL) {
		int msgarray_idx = 0;

		*msgarray = malloc(input->stream->nmsg->n_payloads * sizeof(void *));
		if (*msgarray == NULL) {
			nmsg__nmsg__free_unpacked(input->stream->nmsg, NULL);
			input->stream->nmsg = NULL;
			return (nmsg_res_memfail);
		}
		*n_msg = input->stream->nmsg->n_payloads;

		for (unsigned i = 0; i < input->stream->nmsg->n_payloads; i++) {
			Nmsg__NmsgPayload *np;
			nmsg_message_t msg;

			/* detach payload */
			np = input->stream->nmsg->payloads[i];
			input->stream->nmsg->payloads[i] = NULL;

			/* filter payload */
			if (!_input_nmsg_filter(input, i, np)) {
				_nmsg_payload_free(&np);
				*n_msg -= 1;
				continue;
			}

			/* convert payload to message object */
			msg = _nmsg_message_from_payload(np);
			if (msg == NULL) {
				free(*msgarray);
				*msgarray = NULL;
				*n_msg = 0;
				nmsg__nmsg__free_unpacked(input->stream->nmsg, NULL);
				input->stream->nmsg = NULL;
				return (nmsg_res_memfail);
			}
			(*msgarray)[msgarray_idx] = msg;
			msgarray_idx += 1;
		}

		input->stream->nmsg->n_payloads = 0;
		free(input->stream->nmsg->payloads);
		input->stream->nmsg->payloads = NULL;
		nmsg__nmsg__free_unpacked(input->stream->nmsg, NULL);
		input->stream->nmsg = NULL;
	} else {
		*msgarray = NULL;
		*n_msg = 0;
	}

	return (res);
}
