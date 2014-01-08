/*
 * Copyright (c) 2009-2013 by Farsight Security, Inc.
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

/* Forward. */

static nmsg_res read_file(nmsg_input_t, ssize_t *);
static nmsg_res do_read_file(nmsg_input_t, ssize_t, ssize_t);
static nmsg_res do_read_sock(nmsg_input_t, ssize_t);

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
	if (_input_nmsg_filter(input, input->stream->np_index, np) == false) {
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
			if (input->stop)
				break;
			res = input->stream->stream_read_fp(input, &input->stream->nmsg);
			if (res == nmsg_res_again)
				continue;
			if (res != nmsg_res_success)
				return (res);

			nmsg = input->stream->nmsg;
			for (n = 0; n < nmsg->n_payloads; n++) {
				np = nmsg->payloads[n];
				if (_input_nmsg_filter(input, n, np)) {
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
			if (input->stop)
				break;
			res = input->stream->stream_read_fp(input, &input->stream->nmsg);
			if (res == nmsg_res_again)
				continue;
			if (res != nmsg_res_success)
				return (res);

			nmsg = input->stream->nmsg;
			for (n = 0; n < nmsg->n_payloads; n++) {
				np = nmsg->payloads[n];
				if (_input_nmsg_filter(input, n, np)) {
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
			input->stream->nmsg = NULL;
			if (n_payloads == cnt)
				break;
		}
	}

	return (nmsg_res_success);
}

bool
_input_nmsg_filter(nmsg_input_t input, unsigned idx, Nmsg__NmsgPayload *np) {
	assert(input->stream->nmsg != NULL);

	/* payload crc */
	if (input->stream->nmsg->n_payload_crcs >= (idx + 1)) {
		uint32_t wire_crc = input->stream->nmsg->payload_crcs[idx];
		uint32_t calc_crc = my_crc32c(np->payload.data, np->payload.len);
		if (ntohl(wire_crc) != calc_crc) {
			_nmsg_dprintf(1, "libnmsg: WARNING: crc mismatch (%x != %x) [%s]\n",
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
_input_nmsg_unpack_container(nmsg_input_t input, Nmsg__Nmsg **nmsg,
			     uint8_t *buf, size_t buf_len)
{
	nmsg_res res = nmsg_res_success;

	input->stream->nc_size = buf_len + NMSG_HDRLSZ_V2;
	_nmsg_dprintf(6, "%s: unpacking container len= %zd\n", __func__, buf_len);

	if (input->stream->flags & NMSG_FLAG_FRAGMENT) {
		res = _input_frag_read(input, nmsg, buf, buf_len);
	} else if (input->stream->flags & NMSG_FLAG_ZLIB) {
		size_t u_len;
		u_char *u_buf;

		res = nmsg_zbuf_inflate(input->stream->zb, buf_len, buf, &u_len, &u_buf);
		if (res != nmsg_res_success)
			return (res);
		*nmsg = nmsg__nmsg__unpack(NULL, u_len, u_buf);
		free(u_buf);
		if (*nmsg == NULL)
			return (nmsg_res_parse_error);
	} else {
		*nmsg = nmsg__nmsg__unpack(NULL, buf_len, buf);
		if (*nmsg == NULL)
			return (nmsg_res_parse_error);
	}

	return (res);
}

nmsg_res
_input_nmsg_unpack_container2(const uint8_t *buf, size_t buf_len,
			      unsigned flags, Nmsg__Nmsg **nmsg)
{
	nmsg_res res;

	/* fragmented containers aren't handled by this function */
	if (flags & NMSG_FLAG_FRAGMENT)
		return (nmsg_res_failure);

	if (flags & NMSG_FLAG_ZLIB) {
		size_t u_len;
		u_char *u_buf;
		nmsg_zbuf_t zb;

		zb = nmsg_zbuf_inflate_init();
		if (zb == NULL)
			return (nmsg_res_memfail);
		res = nmsg_zbuf_inflate(zb, buf_len, (uint8_t *) buf, &u_len, &u_buf);
		nmsg_zbuf_destroy(&zb);
		if (res != nmsg_res_success)
			return (res);
		*nmsg = nmsg__nmsg__unpack(NULL, u_len, u_buf);
		free(u_buf);
		if (*nmsg == NULL)
			return (nmsg_res_failure);
	} else {
		*nmsg = nmsg__nmsg__unpack(NULL, buf_len, buf);
		if (*nmsg == NULL)
			return (nmsg_res_failure);
	}

	return (nmsg_res_success);
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
	res = _input_nmsg_unpack_container(input, nmsg, input->stream->buf->pos, msgsize);
	input->stream->buf->pos += msgsize;

	return (res);
}

nmsg_res
_input_nmsg_read_container_sock(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t msgsize;
	struct nmsg_buf *buf = input->stream->buf;

	assert(input->stream->type == nmsg_stream_type_sock);

	/* read the NMSG container */
	_nmsg_buf_reset(buf);
	res = do_read_sock(input, buf->bufsz);
	if (res != nmsg_res_success) {
		if (res == nmsg_res_read_failure)
			return (res);
		else
			/* forward compatibility */
			return (nmsg_res_again);
	}
	if (_nmsg_buf_avail(buf) < NMSG_HDRLSZ_V2)
		return (nmsg_res_failure);

	/* deserialize the NMSG header */
	res = _input_nmsg_deserialize_header(buf->pos,
					     _nmsg_buf_avail(buf),
					     &msgsize,
					     &input->stream->flags);
	if (res != nmsg_res_success)
		return (res);
	buf->pos += NMSG_HDRLSZ_V2;

	/* since the input stream is a sock stream, the entire message must
	 * have been read by the call to do_read_sock() */
	if (_nmsg_buf_avail(buf) != msgsize)
		return (nmsg_res_parse_error);

	/* unpack message */
	res = _input_nmsg_unpack_container(input, nmsg, buf->pos, msgsize);
	input->stream->buf->pos += msgsize;

	/* update counters */
	if (*nmsg != NULL) {
		input->stream->count_recv += 1;

		if (input->stream->verify_seqsrc) {
			struct nmsg_seqsrc *seqsrc;

			seqsrc = _input_seqsrc_get(input, *nmsg);
			if (seqsrc != NULL) {
				size_t drop;
				drop = _input_seqsrc_update(input, seqsrc, *nmsg);
				input->stream->count_drop += drop;
			}
		}
	}

	/* expire old outstanding fragments */
	_input_frag_gc(input->stream);

	return (res);
}

#ifdef HAVE_LIBXS
nmsg_res
_input_nmsg_read_container_xs(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	int ret;
	nmsg_res res;
	uint8_t *buf;
	size_t buf_len;
	ssize_t msgsize = 0;
	xs_msg_t xmsg;
	xs_pollitem_t xitems[1];

	/* poll */
	xitems[0].socket = input->stream->xs;
	xitems[0].events = XS_POLLIN;
	ret = xs_poll(xitems, 1, NMSG_RBUF_TIMEOUT);
	if (ret == 0 || (ret == -1 && errno == EINTR))
		return (nmsg_res_again);
	else if (ret == -1)
		return (nmsg_res_read_failure);

	/* initialize XS message object */
	if (xs_msg_init(&xmsg))
		return (nmsg_res_failure);

	/* read the NMSG container */
	if (xs_recvmsg(input->stream->xs, &xmsg, 0) == -1) {
		res = nmsg_res_failure;
		goto out;
	}
	nmsg_timespec_get(&input->stream->now);

	/* get buffer from the XS message */
	buf = xs_msg_data(&xmsg);
	buf_len = xs_msg_size(&xmsg);
	if (buf_len < NMSG_HDRLSZ_V2) {
		res = nmsg_res_failure;
		goto out;
	}

	/* deserialize the NMSG header */
	res = _input_nmsg_deserialize_header(buf, buf_len, &msgsize, &input->stream->flags);
	if (res != nmsg_res_success)
		goto out;
	buf += NMSG_HDRLSZ_V2;

	/* the entire message must have been read by xs_recvmsg() */
	assert((size_t) msgsize == buf_len - NMSG_HDRLSZ_V2);

	/* unpack message */
	res = _input_nmsg_unpack_container(input, nmsg, buf, msgsize);

	/* update seqsrc counts */
	if (input->stream->verify_seqsrc && *nmsg != NULL) {
		struct nmsg_seqsrc *seqsrc = _input_seqsrc_get(input, *nmsg);
		if (seqsrc != NULL)
			_input_seqsrc_update(input, seqsrc, *nmsg);
	}

	/* expire old outstanding fragments */
	_input_frag_gc(input->stream);

out:
	xs_msg_close(&xmsg);
	return (res);
}
#endif /* HAVE_LIBXS */

nmsg_res
_input_nmsg_deserialize_header(const uint8_t *buf, size_t buf_len,
			       ssize_t *msgsize, unsigned *flags)
{
	static const char magic[] = NMSG_MAGIC;
	uint16_t version;

	if (buf_len < NMSG_LENHDRSZ_V2)
		return (nmsg_res_failure);

	/* check magic */
	if (memcmp(buf, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	buf += sizeof(magic);

	/* check version */
	load_net16(buf, &version);
	if ((version & 0xFF) != 2U)
		return (nmsg_res_version_mismatch);
	*flags = version >> 8;
	buf += sizeof(version);

	/* load message (container) size */
	load_net32(buf, msgsize);

	return (nmsg_res_success);
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
do_read_sock(nmsg_input_t input, ssize_t bytes_max) {
	int ret;
	ssize_t bytes_read;
	struct nmsg_buf *buf = input->stream->buf;
	socklen_t addr_len = sizeof(struct sockaddr_storage);

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

	return (nmsg_res_success);
}
