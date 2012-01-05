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
_input_pcap_read(nmsg_input_t input, nmsg_message_t *msg) {
	nmsg_res res;
	size_t sz;
	struct nmsg_ipdg dg;
	struct timespec ts;
	uint8_t *pbuf;

	/* get next ip datagram from pcap source */
	res = nmsg_pcap_input_read(input->pcap, &dg, &ts);
	if (res != nmsg_res_success)
		return (res);

	/* convert ip datagram to payload */
	res = nmsg_msgmod_ipdg_to_payload(input->msgmod, input->clos, &dg,
					  &pbuf, &sz);
	if (res != nmsg_res_pbuf_ready)
		return (res);

	/* encapsulate nmsg payload */
	*msg = nmsg_message_from_raw_payload(input->msgmod->plugin->vendor.id,
					     input->msgmod->plugin->msgtype.id,
					     pbuf, sz, &ts);
	if (*msg == NULL) {
		free(pbuf);
		return (nmsg_res_memfail);
	}

	return (nmsg_res_success);
}

nmsg_res
_input_pcap_read_raw(nmsg_input_t input, nmsg_message_t *msg) {
	return (nmsg_msgmod_pkt_to_payload(input->msgmod, input->clos, input->pcap, msg));
}
