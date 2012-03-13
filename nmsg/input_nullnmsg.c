/*
 * Copyright (c) 2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
	assert((size_t) msgsize == buf_len - NMSG_HDRLSZ_V2);

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
			if (_input_nmsg_filter(input, i, np)) {
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

		nmsg__nmsg__free_unpacked(input->stream->nmsg, NULL);
		input->stream->nmsg = NULL;
	} else {
		*msgarray = NULL;
		*n_msg = 0;
	}

	return (res);
}
