/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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

/* Private. */

static nmsg_res
io_read_payload_nmsg(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload **np) {
	return (nmsg_input_next(iothr->io_input->input, np));
}

static nmsg_res
io_read_payload_pcap(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload **np)
{
	nmsg_res res;
	size_t sz;
	struct nmsg_ipdg dg;
	uint8_t *pbuf;
	unsigned vid, msgtype;
	struct nmsg_io_input *io_input = iothr->io_input;

	vid = io_input->pbmod->vendor.id;
	msgtype = io_input->pbmod->msgtype.id;

	/* get next ip datagram from pcap source */
	res = nmsg_pcap_input_next(io_input->input->pcap, &dg);
	if (res != nmsg_res_success)
		return (res);

	/* convert ip datagram to protobuf payload */
	res = nmsg_pbmod_ipdg_to_pbuf(io_input->input->pcap->pbmod,
				      io_input->clos, &dg, &pbuf, &sz);
	if (res != nmsg_res_pbuf_ready)
		return (res);

	/* convert protobuf data to nmsg payload */
	*np = nmsg_payload_make(pbuf, sz, vid, msgtype, &iothr->now);
	if (*np == NULL) {
		free(pbuf);
		return (nmsg_res_memfail);
	}

	return (nmsg_res_success);
}

static nmsg_res
io_read_payload_pres(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload **np)
{
	char line[1024];
	nmsg_res res;
	size_t sz;
	uint8_t *pbuf;
	unsigned vid, msgtype;
	struct nmsg_io_input *io_input = iothr->io_input;

	vid = io_input->pbmod->vendor.id;
	msgtype = io_input->pbmod->msgtype.id;

	while (fgets(line, sizeof(line), io_input->input->pres->fp) != NULL) {
		res = nmsg_pbmod_pres_to_pbuf(io_input->pbmod, io_input->clos,
					      line);
		if (res == nmsg_res_failure)
			return (res);
		if (res == nmsg_res_success)
			continue;
		if (res != nmsg_res_pbuf_ready)
			return (res);

		/* pbuf now ready, finalize and convert to nmsg payload */
		res = nmsg_pbmod_pres_to_pbuf_finalize(io_input->pbmod,
						       io_input->clos,
						       &pbuf, &sz);
		if (res != nmsg_res_success)
			return (res);
		*np = nmsg_payload_make(pbuf, sz, vid, msgtype, &iothr->now);
		if (*np == NULL) {
			free(pbuf);
			return (nmsg_res_memfail);
		}

		return (nmsg_res_success);
	}

	return (nmsg_res_failure);
}
