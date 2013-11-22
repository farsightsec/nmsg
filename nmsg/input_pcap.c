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
