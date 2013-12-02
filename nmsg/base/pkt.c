/* pkt nmsg message module */

/*
 * Copyright (c) 2010 by Farsight Security, Inc.
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

#include "pkt.pb-c.h"

/* Exported via module context. */

static nmsg_res
pkt_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m);

/* Data. */

struct nmsg_msgmod_field pkt_fields[] = {
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "len_frame",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "payload",
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { NMSG_VENDOR_ISC_PKT_ID, NMSG_VENDOR_ISC_PKT_NAME },

	.pbdescr = &nmsg__isc__pkt__descriptor,
	.fields = pkt_fields,
	.pkt_to_payload = pkt_pkt_to_payload,
};

static nmsg_res
pkt_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m) {
	Nmsg__Isc__Pkt *pkt;
	const uint8_t *pkt_data;
	int snaplen;
	nmsg_res res;
	size_t buf_sz;
	struct pcap_pkthdr *pkt_hdr;
	struct timespec ts;
	uint8_t *buf;

	/* get a packet and return it as an encapsulated message object */
	res = nmsg_pcap_input_read_raw(pcap, &pkt_hdr, &pkt_data, &ts);
	if (res != nmsg_res_success)
		return (res);

	/* get snaplen */
	snaplen = nmsg_pcap_snapshot(pcap);
	if (snaplen == 0)
		snaplen = 65535;

	/* allocate space for serialized payload */
	buf = malloc(snaplen + 64);
	if (buf == NULL)
		return (nmsg_res_memfail);

	/* initialize the Nmsg__Isc__Pkt object */
	pkt = calloc(1, sizeof(*pkt));
	if (pkt == NULL) {
		free(buf);
		return (nmsg_res_memfail);
	}
	nmsg__isc__pkt__init(pkt);

	pkt->payload.len = pkt_hdr->caplen;
	pkt->payload.data = (uint8_t *) pkt_data;
	pkt->len_frame = pkt_hdr->len;
	pkt->has_len_frame = 1;
	buf_sz = nmsg__isc__pkt__pack(pkt, buf);
	pkt->payload.len = 0;
	pkt->payload.data = NULL;
	*m = nmsg_message_from_raw_payload(NMSG_VENDOR_ISC_ID,
					   NMSG_VENDOR_ISC_PKT_ID,
					   buf, buf_sz, &ts);
	free(pkt);
	return (nmsg_res_success);
}
