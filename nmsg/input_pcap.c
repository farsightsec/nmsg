/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
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

nmsg_buf
nmsg_input_open_pcap(pcap_t *phandle) {
	struct nmsg_buf *buf;

	buf = calloc(1, sizeof(*buf));
	if (buf == NULL)
		return (NULL);

	buf->type = nmsg_buf_type_read_pcap;

	buf->pcap.handle = phandle;
	buf->pcap.datalink = pcap_datalink(phandle);
	buf->pcap.reasm = reasm_ip_new();
	if (buf->pcap.reasm == NULL) {
		free(buf);
		return (NULL);
	}

	return (buf);
}

/* Private. */

#include <stdio.h>

static nmsg_res
input_next_pcap(nmsg_buf buf, Nmsg__Nmsg **nmsg) {
	const u_char *pkt_data;
	struct pcap_pkthdr *pkt_header;
	int ret;
	unsigned i;

	*nmsg = calloc(1, sizeof(**nmsg));
	if (*nmsg == NULL)
		return (nmsg_res_memfail);
	nmsg__nmsg__init(*nmsg);

	assert(buf->type == nmsg_buf_type_read_pcap);
	assert(nmsg != NULL);

	for (i = 0; i < NMSG_RPCAPSZ; i++) {
		ret = pcap_next_ex(buf->pcap.handle, &pkt_header, &pkt_data);
		if (ret == -1) {
			fprintf(stderr, "pcap_next_ex() returned -1\n");
			free(*nmsg);
			return (nmsg_res_pcap_error);
		} else if (ret == -2) {
			fprintf(stderr, "pcap_next_ex() returned -2\n");
			if (i == 0) {
				free(*nmsg);
				*nmsg = NULL;
				return (nmsg_res_eof);
			} else {
				break;
			}
		}
		fprintf(stderr, "%s: got a packet len=%u\n", __func__, pkt_header->len);
	}
	fprintf(stderr, "%s: queued up some packets\n", __func__);

	return (nmsg_res_success);
}
