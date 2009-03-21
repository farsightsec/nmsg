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

/* Import. */

#include <stdio.h>

/* Export. */

nmsg_pcap
nmsg_input_open_pcap(pcap_t *phandle) {
	struct nmsg_pcap *pcap;

	pcap = calloc(1, sizeof(*pcap));
	if (pcap == NULL)
		return (NULL);

	pcap->handle = phandle;
	pcap->datalink = pcap_datalink(phandle);
	pcap->new_pkt = calloc(1, NMSG_IPSZ_MAX);
	pcap->reasm = reasm_ip_new();
	if (pcap->reasm == NULL) {
		free(pcap->new_pkt);
		free(pcap);
		return (NULL);
	}
	reasm_ip_set_timeout(pcap->reasm, 60);

	return (pcap);
}

nmsg_res
nmsg_input_close_pcap(nmsg_pcap *pcap) {
	reasm_ip_free((*pcap)->reasm);
	pcap_close((*pcap)->handle);
	free((*pcap)->new_pkt);
	free(*pcap);
	*pcap = NULL;
	return (nmsg_res_success);
}

nmsg_res
nmsg_input_next_pcap(nmsg_pcap pcap, struct nmsg_ipdg *dg) {
	const u_char *pkt_data;
	int pcap_res;
	struct pcap_pkthdr *pkt_hdr;

	/* get the next frame from the libpcap source */
	pcap_res = pcap_next_ex(pcap->handle, &pkt_hdr, &pkt_data);
	if (pcap_res == -1)
		return (nmsg_res_pcap_error);
	if (pcap_res == -2)
		return (nmsg_res_eof);

	/* parse the frame */
	return (nmsg_ipdg_parse_pcap(dg, pcap, pkt_hdr, pkt_data));
}
