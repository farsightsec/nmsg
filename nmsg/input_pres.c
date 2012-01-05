/*
 * Copyright (c) 2009-2012 by Internet Systems Consortium, Inc. ("ISC")
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
_input_pres_read(nmsg_input_t input, nmsg_message_t *msg) {
	char line[1024];
	nmsg_res res;
	size_t sz;
	struct timespec ts;
	uint8_t *pbuf;

	while (fgets(line, sizeof(line), input->pres->fp) != NULL) {
		res = nmsg_msgmod_pres_to_payload(input->msgmod, input->clos,
						  line);
		if (res == nmsg_res_failure)
			return (res);
		if (res == nmsg_res_success)
			continue;
		if (res != nmsg_res_pbuf_ready)
			return (res);

		/* payload ready, finalize and convert to nmsg payload */
		nmsg_timespec_get(&ts);
		res = nmsg_msgmod_pres_to_payload_finalize(input->msgmod,
							   input->clos,
							   &pbuf, &sz);
		if (res != nmsg_res_success)
			return (res);
		*msg = nmsg_message_from_raw_payload(input->msgmod->plugin->vendor.id,
						     input->msgmod->plugin->msgtype.id,
						     pbuf, sz, &ts);
		if (*msg == NULL) {
			free(pbuf);
			return (nmsg_res_memfail);
		}

		return (nmsg_res_success);
	}

	return (nmsg_res_eof);
}
