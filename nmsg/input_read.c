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

static nmsg_res
input_read_nmsg(nmsg_input_t input, Nmsg__NmsgPayload **np) {
	nmsg_res res;

	if (input->stream->nmsg != NULL &&
	    input->stream->np_index >= input->stream->nmsg->n_payloads - 1)
	{
		input->stream->nmsg->n_payloads = 0;
		nmsg__nmsg__free_unpacked(input->stream->nmsg, NULL);
		input->stream->nmsg = NULL;
	} else {
		input->stream->np_index += 1;
	}

	if (input->stream->nmsg == NULL) {
		res = input_read_nmsg_container(input, &input->stream->nmsg);
		if (res != nmsg_res_success)
			return (res);
		input->stream->np_index = 0;
	}

	/* pass a pointer to the payload to the caller */
	*np = input->stream->nmsg->payloads[input->stream->np_index];

	/* detach the payload from the original nmsg container */
	input->stream->nmsg->payloads[input->stream->np_index] = NULL;

	return (nmsg_res_success);
}

static nmsg_res
input_read_nmsg_container(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail, msgsize;
	struct nmsg_buf *buf;

	buf = input->stream->buf;

	/* read the header */
	res = read_header(input, &msgsize);
	if (res != nmsg_res_success &&
	    input->stream->type == nmsg_stream_type_sock)
	{
		/* forward compatibility */
		return (nmsg_res_again);
	}
	if (res != nmsg_res_success)
		return (res);

	/* if the input stream is a file stream, read the nmsg container */
	bytes_avail = nmsg_buf_avail(buf);
	if (input->stream->type == nmsg_stream_type_file &&
	    bytes_avail < msgsize)
	{
		ssize_t bytes_to_read = msgsize - bytes_avail;

		res = read_input(input, bytes_to_read, bytes_to_read);
		if (res != nmsg_res_success)
			return (res);
	}
	/* if the input stream is a sock stream, then the entire message must
	 * have been read by the call to read_header() */
	else if (input->stream->type == nmsg_stream_type_sock)
		assert(nmsg_buf_avail(buf) == msgsize);

	/* unpack message */
	if (input->stream->flags & NMSG_FLAG_FRAGMENT) {
		res = read_input_frag(input, msgsize, nmsg);
	} else if (input->stream->flags & NMSG_FLAG_ZLIB) {
		size_t ulen;
		u_char *ubuf;

		res = nmsg_zbuf_inflate(input->stream->zb, msgsize, buf->pos,
					&ulen, &ubuf);
		if (res != nmsg_res_success)
			return (res);
		*nmsg = nmsg__nmsg__unpack(NULL, ulen, ubuf);
		assert(*nmsg != NULL);
		free(ubuf);
	} else {
		*nmsg = nmsg__nmsg__unpack(NULL, msgsize, buf->pos);
		assert(*nmsg != NULL);
	}
	buf->pos += msgsize;

	/* if the input stream is a sock stream, then expire old outstanding
	 * fragments */
	if (input->stream->type == nmsg_stream_type_sock &&
	    input->stream->nfrags > 0 &&
	    input->stream->now.tv_sec - input->stream->lastgc.tv_sec >=
		NMSG_FRAG_GC_INTERVAL)
	{
		gc_frags(input->stream);
		input->stream->lastgc = input->stream->now;
	}

	return (res);
}

static nmsg_res
input_read_pcap(nmsg_input_t input, Nmsg__NmsgPayload **np) {
	nmsg_res res;
	size_t sz;
	struct nmsg_ipdg dg;
	struct timespec ts;
	uint8_t *pbuf;

	/* get next ip datagram from pcap source */
	res = nmsg_pcap_input_read(input->pcap, &dg);
	if (res != nmsg_res_success)
		return (res);

	/* convert ip datagram to protobuf payload */
	res = nmsg_pbmod_ipdg_to_pbuf(input->pbmod, input->clos, &dg,
				      &pbuf, &sz);
	if (res != nmsg_res_pbuf_ready)
		return (res);

	/* convert protobuf data to nmsg payload */
	nmsg_timespec_get(&ts);
	*np = nmsg_payload_make(pbuf, sz, input->pbmod->vendor.id,
				input->pbmod->msgtype.id, &ts);
	if (*np == NULL) {
		free(pbuf);
		return (nmsg_res_memfail);
	}

	return (nmsg_res_success);
}

static nmsg_res
input_read_pres(nmsg_input_t input, Nmsg__NmsgPayload **np)
{
	char line[1024];
	nmsg_res res;
	size_t sz;
	struct timespec ts;
	uint8_t *pbuf;

	while (fgets(line, sizeof(line), input->pres->fp) != NULL) {
		res = nmsg_pbmod_pres_to_pbuf(input->pbmod, input->clos,
					      line);
		if (res == nmsg_res_failure)
			return (res);
		if (res == nmsg_res_success)
			continue;
		if (res != nmsg_res_pbuf_ready)
			return (res);

		/* pbuf now ready, finalize and convert to nmsg payload */
		nmsg_timespec_get(&ts);
		res = nmsg_pbmod_pres_to_pbuf_finalize(input->pbmod,
						       input->clos,
						       &pbuf, &sz);
		if (res != nmsg_res_success)
			return (res);
		*np = nmsg_payload_make(pbuf, sz, input->pbmod->vendor.id,
					input->pbmod->msgtype.id, &ts);
		if (*np == NULL) {
			free(pbuf);
			return (nmsg_res_memfail);
		}

		return (nmsg_res_success);
	}

	return (nmsg_res_failure);
}
