/* pkt nmsg message module */

/*
 * Copyright (c) 2010 by Internet Systems Consortium, Inc. ("ISC")
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

#include "pkt.pb-c.c"

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
	.msgver = NMSG_MSGMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { NMSG_VENDOR_ISC_PKT_ID, NMSG_VENDOR_ISC_PKT_NAME },

	.pbdescr = &nmsg__isc__pkt__descriptor,
	.fields = pkt_fields,
	.pkt_to_payload = pkt_pkt_to_payload,
};

static nmsg_res
pkt_pkt_to_payload(void *clos, nmsg_pcap_t pcap, nmsg_message_t *m) {
	nmsg_res res;

	/* get a packet and return it as an encapsulated message object */
	res = nmsg_res_failure;
	while (res != nmsg_res_success) {
		struct timespec ts;
		struct pcap_pkthdr *pkt_hdr;
		const uint8_t *pkt_data;

		res = nmsg_pcap_input_read_raw(pcap, &pkt_hdr, &pkt_data, &ts);
		if (res == nmsg_res_success) {
			Nmsg__Isc__Pkt *pkt;
			int snaplen;
			size_t buf_sz;
			uint8_t *buf;

			/* get snaplen */
			snaplen = nmsg_pcap_snapshot(pcap);
			if (snaplen == 0)
				snaplen = 65536;

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
		} else if (res == nmsg_res_again) {
			continue;
		} else {
			return (res);
		}
	}
	return (res);
}
