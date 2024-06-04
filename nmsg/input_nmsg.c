/*
 * Copyright (c) 2009-2019 by Farsight Security, Inc.
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

static nmsg_res file_read_header(struct nmsg_stream_input *);
static nmsg_res do_read_file(struct nmsg_stream_input *, ssize_t, ssize_t);
static nmsg_res do_read_sock(struct nmsg_stream_input *, ssize_t);

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
	if (*msg == NULL) {
		_nmsg_payload_free(&np);
		return (nmsg_res_memfail);
	}

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
	struct nmsg_stream_input *istr = input->stream;
	nmsg_res res = nmsg_res_success;

	istr->nc_size = buf_len + istr->si_hdr.h_header_size;
	_nmsg_dprintf(6, "%s: unpacking container len= %zd\n", __func__, buf_len);

	if (NMSG_STR_IS_FRAGMENTED(istr))
		res = _input_frag_read(input, nmsg, buf, buf_len);
	else if (NMSG_STR_IS_COMPRESSED(istr)) {
		size_t u_len;
		u_char *u_buf;

		res = nmsg_decompress(NMSG_STR_COMPRESSION_TYPE(istr), buf, buf_len, &u_buf, &u_len);
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

	if (res == nmsg_res_success)
		istr->count_recv++;

	return (res);
}

nmsg_res
_input_nmsg_unpack_container2(const uint8_t *buf, size_t buf_len,
			      const struct nmsg_header *hdr, Nmsg__Nmsg **nmsg)
{
	nmsg_res res;

	/* fragmented containers aren't handled by this function */
	if (hdr->h_is_frag)
		return (nmsg_res_failure);

	if (hdr->h_compression != NMSG_COMPRESSION_NONE) {
		size_t u_len;
		u_char *u_buf;

		res = nmsg_decompress(hdr->h_compression, buf, buf_len, &u_buf, &u_len);
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
	struct nmsg_stream_input *istr = input->stream;
	struct nmsg_buf *buf = istr->buf;
	nmsg_res res;
	ssize_t bytes_avail, msgsize;

	assert(istr->type == nmsg_stream_type_file);

	/* First, read the NMSG header. */
	res = file_read_header(istr);
	if (res != nmsg_res_success)
		return (res);

	msgsize = istr->si_hdr.h_msgsize;

	/* ensure that the full NMSG container is available */
	bytes_avail = _nmsg_buf_avail(buf);
	if (bytes_avail < msgsize) {
		ssize_t bytes_to_read = msgsize - bytes_avail;

		if (bytes_avail == 0)		/* Read to start of buffer. */
			_nmsg_buf_reset(buf);

		res = do_read_file(istr, bytes_to_read, bytes_to_read);
		if (res != nmsg_res_success)
			return (res);
	}

	/* unpack message */
	res = _input_nmsg_unpack_container(input, nmsg, buf->pos, msgsize);
	buf->pos += msgsize;

	return (res);
}

nmsg_res
_input_nmsg_read_container_sock(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	struct nmsg_stream_input *istr = input->stream;
	struct nmsg_buf *buf = istr->buf;
	nmsg_res res;
	ssize_t msgsize;

	assert(istr->type == nmsg_stream_type_sock);

	/* read the NMSG container */
	_nmsg_buf_reset(buf);
	res = do_read_sock(istr, buf->bufsz);
	if (res != nmsg_res_success) {
		if (res == nmsg_res_read_failure)
			return (res);
		else
			/* forward compatibility */
			return (nmsg_res_again);
	}

	/* deserialize the NMSG header */
	res = _input_nmsg_extract_header(buf->pos, _nmsg_buf_avail(buf), &istr->si_hdr);
	if (res != nmsg_res_success)
		return (res);

	msgsize = istr->si_hdr.h_msgsize;
	buf->pos += istr->si_hdr.h_header_size;

	/* since the input stream is a sock stream, the entire message must
	 * have been read by the call to do_read_sock() */
	if (_nmsg_buf_avail(buf) != msgsize)
		return (nmsg_res_parse_error);

	/* unpack message */
	res = _input_nmsg_unpack_container(input, nmsg, buf->pos, msgsize);
	buf->pos += msgsize;

	/* update counters */
	if (*nmsg != NULL) {

		if (istr->verify_seqsrc) {
			struct nmsg_seqsrc *seqsrc;

			seqsrc = _input_seqsrc_get(input, *nmsg);
			if (seqsrc != NULL) {
				size_t drop;
				drop = _input_seqsrc_update(input, seqsrc, *nmsg);
				istr->count_drop += drop;
			}
		}
	}

	/* expire old outstanding fragments */
	_input_frag_gc(istr);

	return (res);
}

#if defined(HAVE_LIBRDKAFKA) || defined(HAVE_LIBZMQ)
static nmsg_res
_input_process_buffer_into_container(nmsg_input_t input, Nmsg__Nmsg **nmsg, uint8_t *buf, size_t buf_len)
{
	struct nmsg_stream_input *istr = input->stream;
	nmsg_res res;
	ssize_t msgsize;

	if (buf_len < NMSG_HDRLSZ_V2)
		return nmsg_res_failure;

	/* deserialize the NMSG header */
	res = _input_nmsg_extract_header(buf, buf_len, &istr->si_hdr);
	if (res != nmsg_res_success)
		return res;

	msgsize = istr->si_hdr.h_msgsize;
	buf += istr->si_hdr.h_header_size;

	/* the entire message must have been read by caller */
	if ((size_t) msgsize != (buf_len - istr->si_hdr.h_header_size))
		return nmsg_res_parse_error;

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

	return nmsg_res_success;
}
#endif /* defined(HAVE_LIBRDKAFKA) || defined(HAVE_LIBZMQ) */

#ifdef HAVE_LIBRDKAFKA
nmsg_res
_input_nmsg_read_container_kafka(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	uint8_t *buf;
	size_t buf_len;

	res = kafka_read_start(input->stream->kafka, &buf, &buf_len);
	if (res != nmsg_res_success) {
		kafka_read_finish(input->stream->kafka);
		return res;
	}

	nmsg_timespec_get(&input->stream->now);

	res = _input_process_buffer_into_container(input, nmsg, buf, buf_len);

	kafka_read_finish(input->stream->kafka);
	return res;
}
#endif /* HAVE_LIBRDKAFKA */

#ifdef HAVE_LIBZMQ
nmsg_res
_input_nmsg_read_container_zmq(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	struct nmsg_stream_input *istr = input->stream;
	int ret;
	nmsg_res res;
	zmq_msg_t zmsg;
	zmq_pollitem_t zitems[1];

	/* poll */
	zitems[0].socket = istr->zmq;
	zitems[0].events = ZMQ_POLLIN;
	ret = zmq_poll(zitems, 1, NMSG_RBUF_TIMEOUT);
	if (ret == 0 || (ret == -1 && errno == EINTR))
		return (nmsg_res_again);
	else if (ret == -1)
		return (nmsg_res_read_failure);

	/* initialize ZMQ message object */
	if (zmq_msg_init(&zmsg))
		return (nmsg_res_failure);

	/* read the NMSG container */
	if (zmq_recvmsg(istr->zmq, &zmsg, 0) == -1) {
		res = nmsg_res_failure;
		goto out;
	}
	nmsg_timespec_get(&istr->now);

	/* get buffer from the ZMQ message */
	res = _input_process_buffer_into_container(input, nmsg, zmq_msg_data(&zmsg), zmq_msg_size(&zmsg));

out:
	zmq_msg_close(&zmsg);
	return (res);
}
#endif /* HAVE_LIBZMQ */

/*
 * Extract nmsg header-information from a buffer.
 *
 *     buf - Buffer with data.
 * buf_len - Size of buffer, in bytes.
 *     hdr - To hold extracted information.
 *	     The minimum number of bytes needed is returned in
 *	     hdr->h_header_size
 *
 * Returns:
 *	+	   nmsg_res_success - if everything is ok and *hdr is valid
 *	+   nmsg_res_magic_mismatch - if bad magic number
 *	+ nmsg_res_version_mismatch - for header-version mismatch
 *	+	   nmsg_res_failure - if insufficient bytes to extract header
 *	+	   nmsg_res_notimpl - if the message requires an unimplemented
 *				      feature, like an unsupported decompression method
 */
nmsg_res
_input_nmsg_extract_header(const uint8_t *buf, size_t buf_len, struct nmsg_header *hdr)
{
	static const char magic[] = NMSG_MAGIC;
	uint16_t version, flags;
	uint16_t msgsize_v1;

	/* Must have enough data (6 bytes) for magic-number and version/flags. */
	if (buf_len < NMSG_HDRSZ)
		return (nmsg_res_failure);

	/* check magic */
	if (memcmp(buf, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);

	buf += sizeof(magic);
	buf_len -= sizeof(magic);

	/* check version */
	load_net16(buf, &version);
	buf += sizeof(version);
	buf_len -= sizeof(version);

	flags = version >> 8;
	version &= 0xFF;

	hdr->h_version = version;
	hdr->h_flags = flags;
	hdr->h_num_payloads = 0xFFFF;	/* #payloads not known. */
	hdr->h_compression = NMSG_COMPRESSION_NONE;
	hdr->h_is_frag = false;
	hdr->h_has_exthdr = false;

	_nmsg_dprintf(4, "%s: NMSG header version %d\n", __func__, version);

	switch (version) {
	case 1U:
		hdr->h_header_size = NMSG_HDRSZ + NMSG_LENHDRSZ_V1;

		if (buf_len < NMSG_LENHDRSZ_V1)		/* Two-byte length. */
			return (nmsg_res_failure);

		load_net16(buf, &msgsize_v1);
		hdr->h_msgsize = msgsize_v1;

		if (flags & NMSG_FLAG_FRAGMENT)
			hdr->h_is_frag = true;
		if (flags & NMSG_FLAG_ZLIB)
			hdr->h_compression = NMSG_COMPRESSION_ZLIB;
		break;

	case 2U:
		hdr->h_header_size = NMSG_HDRSZ + NMSG_LENHDRSZ_V2;

		if (buf_len < NMSG_LENHDRSZ_V2)		/* Four-byte length. */
			return (nmsg_res_failure);

		/* load message (container) size */
		load_net32(buf, &hdr->h_msgsize);
		buf += 4;

		if (flags & NMSG_FLAG_FRAGMENT)
			hdr->h_is_frag = true;
#if 0
		if (flags & NMSG_FLAG_ZLIB)
			hdr->h_compression = NMSG_COMPRESSION_ZLIB;
#else
		/* Experimental code. */
		hdr->h_compression = NMSG_COMPRESSION_FROM_FLAG_V2(flags);
#endif
		break;

	case 3U:
		/*
		 * V3: 12-byte header, compared to 10-byte for V2.
		 *
		 *  0-3: Magic Number (same as V2)
		 *  4-5: Version/Flags (same size/offset as V2, Flags different)
		 *	 + Flags different to V2
		 *	 +    Bit 0: Fragmentation
		 *	 +    Bit 1: Has extension header (future)
		 *	 + Bits 2-4: Compression-codec
		 *  6-7: Payload-count -- maxes out at 0xfff.  0xffff can mean
		 *			  more than 0xffff payloads.
		 * 8-11: Message size (V2: bytes 6-9)
		 */

		hdr->h_header_size = NMSG_HDRSZ + NMSG_LENHDRSZ_V3;

		if (buf_len < NMSG_LENHDRSZ_V3)
			return (nmsg_res_failure);

		/* Number of payloads in container. */
		load_net16(buf, &hdr->h_num_payloads);
		buf += 2;	/* 2 bytes = 16 bits */

		/* load message (container) size */
		load_net32(buf, &hdr->h_msgsize);
		buf += 4;	/* 4 bytes = 32 bits */

		/* Bits 2-4 (inclusive) hold the compression codec. */
		hdr->h_compression = NMSG_COMPRESSION_FROM_FLAG_V3(flags);

		/* Payload is fragmented. */
		if (flags & NMSG_FLAG_FRAGMENT)
			hdr->h_is_frag = true;

		/* Extension-headers present. */
		if (flags & NMSG_FLAG_V3_EXTHDR)
			hdr->h_has_exthdr = true;
		break;

	default:
		return (nmsg_res_version_mismatch);
	}

#if !HAVE_LIBLZ4
	if (hdr->h_compression == NMSG_COMPRESSION_LZ4 || hdr->h_compression == NMSG_COMPRESSION_LZ4HC) {
		fprintf(stderr, "%s: Error: Header uses LZ4 --- not supported.\n", __func__);
		return (nmsg_res_notimpl);
	}
#endif
#if !HAVE_LIBZSTD
	if (hdr->h_compression == NMSG_COMPRESSION_ZSTD) {
		fprintf(stderr, "%s: Error: Header uses ZSTD --- not supported.\n", __func__);
		return (nmsg_res_notimpl);
	}
#endif
	return (nmsg_res_success);
}

/* Private functions. */

/* Read the header and message-size from a file. */
static nmsg_res
file_read_header(struct nmsg_stream_input *istr)
{
	struct nmsg_buf *buf = istr->buf;
	nmsg_res res;

	/* Try to read an NMSG header. */
	for (;;) {
		ssize_t bytes_avail, bytes_needed;

		/* Ensure minimal header in the buffer. */
		if ((bytes_avail = _nmsg_buf_avail(buf)) == 0) {
			_nmsg_buf_reset(buf);
			bytes_needed = NMSG_HDRSZ + NMSG_LENHDRSZ_V1;
			res = do_read_file(istr, bytes_needed, buf->bufsz);
			if (res != nmsg_res_success)
				return (res);

			bytes_avail = _nmsg_buf_avail(buf);
		}

		res = _input_nmsg_extract_header(buf->pos, bytes_avail, &istr->si_hdr);
		if (res == nmsg_res_success) {
			/* on success, this could consume some data, and leave some in the buffer. */
			break;
		} else if (res == nmsg_res_failure) {
			/*
			 * Got insufficient bytes to extract header.
			 * now read the **exact** amount needed (so buffer-pointers can be reset).
			 */
			bytes_needed = istr->si_hdr.h_header_size - bytes_avail;
			assert(bytes_needed > 0);
			res = do_read_file(istr, bytes_needed, bytes_needed);
			if (res != nmsg_res_success)
				return (res);
		} else {
			_nmsg_dprintf(4, "%s: file_read_header - extract_header returned%d\n", __func__, (int)res);
			return (res); /* pass it up */
		}
	}

	/* Advance pointer by bytes consumed for header. */
	buf->pos += istr->si_hdr.h_header_size;

	return (res);
}

static nmsg_res
do_read_file(struct nmsg_stream_input *istr, ssize_t bytes_needed, ssize_t bytes_max)
{
	ssize_t bytes_read;
	struct nmsg_buf *buf = istr->buf;

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
	nmsg_timespec_get(&istr->now);
	return (nmsg_res_success);
}

static nmsg_res
do_read_sock(struct nmsg_stream_input *istr, ssize_t bytes_max)
{
	int ret;
	ssize_t bytes_read;
	struct nmsg_buf *buf = istr->buf;
	socklen_t addr_len = sizeof(struct sockaddr_storage);

	/* check that we have enough buffer space */
	assert((buf->end + bytes_max) <= (buf->data + NMSG_RBUFSZ));

	if (istr->blocking_io == true) {
		/* poll */
		ret = poll(&istr->pfd, 1, NMSG_RBUF_TIMEOUT);
		if (ret == 0 || (ret == -1 && errno == EINTR))
			return (nmsg_res_again);
		else if (ret == -1)
			return (nmsg_res_read_failure);
	}

	/* read */
	bytes_read = recvfrom(buf->fd, buf->pos, bytes_max, 0,
			      (struct sockaddr *) &istr->addr_ss, &addr_len);
	nmsg_timespec_get(&istr->now);

	if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return (nmsg_res_again);
	if (bytes_read < 0)
		return (nmsg_res_read_failure);
	if (bytes_read == 0)
		return (nmsg_res_eof);
	buf->end = buf->pos + bytes_read;

	return (nmsg_res_success);
}
