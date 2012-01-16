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

/* Forward. */

static nmsg_res read_file(nmsg_input_t, ssize_t *);
static nmsg_res read_sock(nmsg_input_t, ssize_t *);
static nmsg_res do_read_file(nmsg_input_t, ssize_t, ssize_t);
static nmsg_res do_read_sock(nmsg_input_t, ssize_t, ssize_t);

/* Internal functions. */

nmsg_res
_input_nmsg_read(nmsg_input_t input, nmsg_message_t *msg) {
	Nmsg__NmsgPayload *np;
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
		res = input->stream->stream_read_fp(input, &input->stream->nmsg);
		if (res != nmsg_res_success)
			return (res);
		input->stream->np_index = 0;
	}

	/* detach the payload from the original nmsg container */
	np = input->stream->nmsg->payloads[input->stream->np_index];
	input->stream->nmsg->payloads[input->stream->np_index] = NULL;

	/* filter payload */
	if (_input_nmsg_filter(input, np) == false) {
		_nmsg_payload_free(&np);
		return (nmsg_res_again);
	}

	/* pass a pointer to the payload to the caller */
	*msg = _nmsg_message_from_payload(np);
	if (msg == NULL)
		return (nmsg_res_memfail);

	/* possibly sleep a bit if ingress rate control is enabled */
	if (input->stream->brate != NULL)
		_nmsg_brate_sleep(input->stream->brate,
				  input->stream->nc_size,
				  input->stream->nmsg->n_payloads,
				  input->stream->np_index);

	return (nmsg_res_success);
}

nmsg_res
_input_nmsg_loop(nmsg_input_t input, int cnt, nmsg_cb_message cb, void *user) {
	unsigned n;
	nmsg_res res;
	Nmsg__Nmsg *nmsg;
	Nmsg__NmsgPayload *np;
	nmsg_message_t msg;

	if (cnt < 0) {
		/* loop indefinitely */
		for (;;) {
			res = input->stream->stream_read_fp(input, &input->stream->nmsg);
			if (res == nmsg_res_again)
				continue;
			if (res != nmsg_res_success)
				return (res);

			nmsg = input->stream->nmsg;
			for (n = 0; n < nmsg->n_payloads; n++) {
				np = nmsg->payloads[n];
				if (_input_nmsg_filter(input, np)) {
					msg = _nmsg_message_from_payload(np);
					cb(msg, user);
				}
			}
			nmsg->n_payloads = 0;
			free(nmsg->payloads);
			nmsg->payloads = NULL;
			nmsg__nmsg__free_unpacked(nmsg, NULL);
			input->stream->nmsg = NULL;
		}
	} else {
		/* loop until (n_payloads == cnt) */
		int n_payloads = 0;

		for (;;) {
			res = input->stream->stream_read_fp(input, &input->stream->nmsg);
			if (res == nmsg_res_again)
				continue;
			if (res != nmsg_res_success)
				return (res);

			nmsg = input->stream->nmsg;
			for (n = 0; n < nmsg->n_payloads; n++) {
				np = nmsg->payloads[n];
				if (_input_nmsg_filter(input, np)) {
					if (n_payloads == cnt)
						break;
					n_payloads += 1;
					msg = _nmsg_message_from_payload(np);
					cb(msg, user);
				}
			}
			nmsg->n_payloads = 0;
			free(nmsg->payloads);
			nmsg->payloads = NULL;
			nmsg__nmsg__free_unpacked(nmsg, NULL);
			if (n_payloads == cnt)
				break;
			input->stream->nmsg = NULL;
		}
	}

	return (nmsg_res_success);
}

bool
_input_nmsg_filter(nmsg_input_t input, Nmsg__NmsgPayload *np) {
	unsigned idx = input->stream->np_index;

	assert(input->stream->nmsg != NULL);

	/* payload crc */
	if (input->stream->nmsg->n_payload_crcs >= (idx + 1)) {
		uint32_t wire_crc = input->stream->nmsg->payload_crcs[idx];
		uint32_t calc_crc = nmsg_crc32c(np->payload.data, np->payload.len);
		if (wire_crc != calc_crc) {
			fprintf(stderr, "libnmsg: WARNING: crc mismatch (%x != %x) [%s]\n",
				calc_crc, wire_crc, __func__);
			return (false);
		}
	}

	/* (vid, msgtype) */
	if (input->do_filter == true &&
	    (input->filter_vid != np->vid ||
	     input->filter_msgtype != np->msgtype))
	{
		return (false);
	}

	/* source */
	if (input->stream->source > 0 &&
	    input->stream->source != np->source)
	{
		return (false);
	}

	/* operator */
	if (input->stream->operator > 0 &&
	    input->stream->operator != np->operator_)
	{
		return (false);
	}

	/* group */
	if (input->stream->group > 0 &&
	    input->stream->group != np->group)
	{
		return (false);
	}

	/* all passed */
	return (true);
}

nmsg_res
_input_nmsg_unpack_container(nmsg_input_t input, Nmsg__Nmsg **nmsg, ssize_t msgsize) {
	nmsg_res res = nmsg_res_success;

	input->stream->nc_size = msgsize + NMSG_HDRLSZ_V2;
	if (_nmsg_global_debug >= 6)
		fprintf(stderr, "%s: unpacking container len= %zd\n", __func__, msgsize);

	if (input->stream->flags & NMSG_FLAG_FRAGMENT) {
		res = _input_frag_read(input, msgsize, nmsg);
	} else if (input->stream->flags & NMSG_FLAG_ZLIB) {
		size_t ulen;
		u_char *ubuf;

		res = nmsg_zbuf_inflate(input->stream->zb, msgsize,
					input->stream->buf->pos,
					&ulen, &ubuf);
		if (res != nmsg_res_success)
			return (res);
		*nmsg = nmsg__nmsg__unpack(NULL, ulen, ubuf);
		assert(*nmsg != NULL);
		free(ubuf);
	} else {
		*nmsg = nmsg__nmsg__unpack(NULL, msgsize, input->stream->buf->pos);
		assert(*nmsg != NULL);
	}
	input->stream->buf->pos += msgsize;

	return (res);
}

nmsg_res
_input_nmsg_read_container_file(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail, msgsize = 0;

	assert(input->stream->type == nmsg_stream_type_file);

	/* read */
	res = read_file(input, &msgsize);
	if (res != nmsg_res_success)
		return (res);

	/* ensure that the full NMSG container is available */
	bytes_avail = _nmsg_buf_avail(input->stream->buf);
	if (bytes_avail < msgsize) {
		ssize_t bytes_to_read = msgsize - bytes_avail;

		res = do_read_file(input, bytes_to_read, bytes_to_read);
		if (res != nmsg_res_success)
			return (res);
	}

	/* unpack message */
	res = _input_nmsg_unpack_container(input, nmsg, msgsize);

	return (res);
}

nmsg_res
_input_nmsg_read_container_sock(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t msgsize;
	struct nmsg_seqsrc *seqsrc = NULL;

	assert(input->stream->type == nmsg_stream_type_sock);

	/* read the NMSG container */
	res = read_sock(input, &msgsize);
	if (res != nmsg_res_success) {
		if (res == nmsg_res_read_failure)
			return (res);
		else
			/* forward compatibility */
			return (nmsg_res_again);
	}
	if (res != nmsg_res_success)
		return (res);

	/* since the input stream is a sock stream, the entire message must
	 * have been read by the call to read_header() */
	assert(_nmsg_buf_avail(input->stream->buf) == msgsize);

	/* unpack message */
	res = _input_nmsg_unpack_container(input, nmsg, msgsize);

	/* update seqsrc counts */
	if (*nmsg != NULL) {
		seqsrc = _input_seqsrc_get(input, *nmsg);
		if (seqsrc != NULL)
			_input_seqsrc_update(input, seqsrc, *nmsg);
	}

	/* expire old outstanding fragments */
	_input_frag_gc(input->stream);

	return (res);
}

nmsg_res
_input_nmsg_read_container_zmq(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	assert(0);
}

/* Private functions. */

static nmsg_res
read_file(nmsg_input_t input, ssize_t *msgsize) {
	static const char magic[] = NMSG_MAGIC;

	bool reset_buf = false;
	ssize_t bytes_avail, bytes_needed, lenhdrsz;
	nmsg_res res = nmsg_res_failure;
	uint16_t version;
	struct nmsg_buf *buf = input->stream->buf;

	/* ensure we have the (magic, version) header fields */
	bytes_avail = _nmsg_buf_avail(buf);
	if (bytes_avail < NMSG_HDRSZ) {
		assert(bytes_avail >= 0);
		bytes_needed = NMSG_HDRSZ - bytes_avail;
		if (bytes_avail == 0) {
			_nmsg_buf_reset(buf);
			res = do_read_file(input, bytes_needed, buf->bufsz);
		} else {
			/* the (magic, version) header fields were split */
			res = do_read_file(input, bytes_needed, bytes_needed);
			reset_buf = true;
		}
		if (res != nmsg_res_success)
			return (res);
	}
	bytes_avail = _nmsg_buf_avail(buf);
	assert(bytes_avail >= NMSG_HDRSZ);

	/* check magic */
	if (memcmp(buf->pos, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	buf->pos += sizeof(magic);

	/* check version */
	load_net16(buf->pos, &version);
	buf->pos += 2;
	if (version == 1U) {
		lenhdrsz = NMSG_LENHDRSZ_V1;
	} else if ((version & 0xFF) == 2U) {
		input->stream->flags = version >> 8;
		version &= 0xFF;
		lenhdrsz = NMSG_LENHDRSZ_V2;
	} else {
		res = nmsg_res_version_mismatch;
		goto read_header_out;
	}

	/* if reset_buf was set, then reading the (magic, version) header
	 * required two read()s. at this point we've consumed all the split
	 * header data, so reset the buffer to avoid overflow.
	 */
	if (reset_buf == true) {
		_nmsg_buf_reset(buf);
		reset_buf = false;
	}

	/* ensure we have the length header field */
	bytes_avail = _nmsg_buf_avail(buf);
	if (bytes_avail < lenhdrsz) {
		if (bytes_avail == 0)
			_nmsg_buf_reset(buf);
		bytes_needed = lenhdrsz - bytes_avail;
		if (bytes_avail == 0) {
			res = do_read_file(input, bytes_needed, buf->bufsz);
		} else {
			/* the length header field was split */
			res = do_read_file(input, bytes_needed, bytes_needed);
			reset_buf = true;
		}
	}
	bytes_avail = _nmsg_buf_avail(buf);
	assert(bytes_avail >= lenhdrsz);

	/* load message size */
	if (version == 1U) {
		load_net16(buf->pos, msgsize);
		buf->pos += 2;
	} else if (version == 2U) {
		load_net32(buf->pos, msgsize);
		buf->pos += 4;
	}

	res = nmsg_res_success;

read_header_out:
	if (reset_buf == true)
		_nmsg_buf_reset(buf);

	return (res);
}

static nmsg_res
do_read_file(nmsg_input_t input, ssize_t bytes_needed, ssize_t bytes_max) {
	ssize_t bytes_read;
	struct nmsg_buf *buf = input->stream->buf;

	/* sanity check */
	assert(bytes_needed <= bytes_max);

	/* check that we have enough buffer space */
	assert((buf->end + bytes_max) <= (buf->data + NMSG_RBUFSZ));

	while (bytes_needed > 0) {
		bytes_read = read(buf->fd, buf->end, bytes_max);
		if (bytes_read < 0)
			return (nmsg_res_failure);
		if (bytes_read == 0)
			return (nmsg_res_eof);
		buf->end += bytes_read;
		bytes_needed -= bytes_read;
		bytes_max -= bytes_read;
	}
	nmsg_timespec_get(&input->stream->now);
	return (nmsg_res_success);
}

static nmsg_res
read_sock(nmsg_input_t input, ssize_t *msgsize) {
	static char magic[] = NMSG_MAGIC;

	ssize_t lenhdrsz;
	nmsg_res res = nmsg_res_failure;
	uint16_t version;
	struct nmsg_buf *buf = input->stream->buf;

	/* initialize *msgsize */
	*msgsize = 0;

	/* read from the socket */
	_nmsg_buf_reset(buf);
	res = do_read_sock(input, NMSG_HDRSZ, buf->bufsz);
	if (res != nmsg_res_success)
		return (res);
	assert(_nmsg_buf_avail(buf) >= NMSG_HDRSZ);

	/* check magic */
	if (memcmp(buf->pos, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	buf->pos += sizeof(magic);

	/* check version */
	load_net16(buf->pos, &version);
	buf->pos += 2;
	if (version == 1U) {
		lenhdrsz = NMSG_LENHDRSZ_V1;
	} else if ((version & 0xFF) == 2U) {
		input->stream->flags = version >> 8;
		version &= 0xFF;
		lenhdrsz = NMSG_LENHDRSZ_V2;
	} else {
		return (nmsg_res_version_mismatch);
	}

	/* ensure we have the length header field */
	assert(_nmsg_buf_avail(buf) >= lenhdrsz);

	/* load message size */
	if (version == 1U) {
		load_net16(buf->pos, msgsize);
		buf->pos += 2;
	} else if (version == 2U) {
		load_net32(buf->pos, msgsize);
		buf->pos += 4;
	}

	res = nmsg_res_success;

	return (res);
}

static nmsg_res
do_read_sock(nmsg_input_t input, ssize_t bytes_needed, ssize_t bytes_max) {
	int ret;
	ssize_t bytes_read;
	struct nmsg_buf *buf = input->stream->buf;
	socklen_t addr_len = sizeof(struct sockaddr_storage);

	/* sanity check */
	assert(bytes_needed <= bytes_max);

	/* check that we have enough buffer space */
	assert((buf->end + bytes_max) <= (buf->data + NMSG_RBUFSZ));

	if (input->stream->blocking_io == true) {
		/* poll */
		ret = poll(&input->stream->pfd, 1, NMSG_RBUF_TIMEOUT);
		if (ret == 0 || (ret == -1 && errno == EINTR))
			return (nmsg_res_again);
		else if (ret == -1)
			return (nmsg_res_read_failure);
	}

	/* read */
	bytes_read = recvfrom(buf->fd, buf->pos, bytes_max, 0,
			      (struct sockaddr *) &input->stream->addr_ss, &addr_len);
	nmsg_timespec_get(&input->stream->now);

	if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return (nmsg_res_again);
	if (bytes_read < 0)
		return (nmsg_res_read_failure);
	if (bytes_read == 0)
		return (nmsg_res_eof);
	buf->end = buf->pos + bytes_read;
	assert(bytes_read >= bytes_needed);

	return (nmsg_res_success);
}