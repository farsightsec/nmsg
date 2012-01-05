/*
 * Copyright (c) 2008-2012 by Internet Systems Consortium, Inc. ("ISC")
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

/* Macros. */

#define reset_estsz(stream) do { (stream)->estsz = NMSG_HDRLSZ_V2; } while (0)

/* Forward. */

static nmsg_res		write_output(nmsg_output_t);
static nmsg_res		write_pbuf(nmsg_output_t);

/* Internal functions. */

nmsg_res
_output_nmsg_flush(nmsg_output_t output) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;

	/* lock output */
	pthread_mutex_lock(&output->stream->lock);

	res = nmsg_res_success;
	nmsg = output->stream->nmsg;

	/* if nmsg container isn't initialized, there is no work to do */
	if (nmsg == NULL)
		goto out;

	/* check if payload needs to be fragmented */
	if (output->stream->estsz > output->stream->buf->bufsz) {
		res = _output_frag_write(output);
		_nmsg_payload_free_all(nmsg);
		reset_estsz(output->stream);
		goto out;
	}

	/* flush output */
	res = write_pbuf(output);
	_nmsg_payload_free_all(nmsg);
	reset_estsz(output->stream);

out:
	/* unlock output */
	pthread_mutex_unlock(&output->stream->lock);

	return (res);
}

nmsg_res
_output_nmsg_write(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__Nmsg *nmsg;
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	size_t np_len;

	/* detach payload from input */
	assert(msg->np != NULL);
	np = msg->np;
	msg->np = NULL;

	/* lock output */
	pthread_mutex_lock(&output->stream->lock);

	res = nmsg_res_success;
	nmsg = output->stream->nmsg;

	/* initialize nmsg container if necessary */
	if (nmsg == NULL) {
		nmsg = output->stream->nmsg = calloc(1, sizeof(Nmsg__Nmsg));
		if (nmsg == NULL) {
			res = nmsg_res_failure;
			goto error_out;
		}
		nmsg__nmsg__init(nmsg);
	}

	/* set source, output, group if necessary */
	if (output->stream->source != 0) {
		np->source = output->stream->source;
		np->has_source = 1;
	}
	if (output->stream->operator != 0) {
		np->operator_ = output->stream->operator;
		np->has_operator_ = 1;
	}
	if (output->stream->group != 0) {
		np->group = output->stream->group;
		np->has_group = 1;
	}

	/* calculate size of serialized payload */
	np_len = _nmsg_payload_size(np);

	/* check for overflow */
	if (output->stream->estsz != NMSG_HDRLSZ_V2 &&
	    output->stream->estsz + np_len + 24 >= output->stream->buf->bufsz)
	{
		/* finalize and write out the container */
		res = write_pbuf(output);
		if (res != nmsg_res_success) {
			_nmsg_payload_free_all(nmsg);
			reset_estsz(output->stream);
			goto error_out;
		}
		_nmsg_payload_free_all(nmsg);
		reset_estsz(output->stream);
	}

	/* sleep a bit if necessary */
	if (output->stream->rate != NULL)
		nmsg_rate_sleep(output->stream->rate);

	/* field tag */
	output->stream->estsz += 1;

	/* varint encoded length */
	output->stream->estsz += 1;
	if (np_len >= (1 << 7))
		output->stream->estsz += 1;
	if (np_len >= (1 << 14))
		output->stream->estsz += 1;
	if (np_len >= (1 << 21))
		output->stream->estsz += 1;

	/* crc field */
	output->stream->estsz += 6;

	/* sequence field */
	if (nmsg->has_sequence)
		output->stream->estsz += 6;

	/* sequence_id field */
	if (nmsg->has_sequence_id)
		output->stream->estsz += 12;

	/* increment estimated size of serialized container */
	output->stream->estsz += np_len;

	/* append payload to container */
	nmsg->payloads = realloc(nmsg->payloads,
				 ++(nmsg->n_payloads) * sizeof(void *));
	if (nmsg->payloads == NULL) {
		res = nmsg_res_memfail;
		goto error_out;
	}
	nmsg->payloads[nmsg->n_payloads - 1] = np;

	/* check if payload needs to be fragmented */
	if (output->stream->estsz > output->stream->buf->bufsz) {
		res = _output_frag_write(output);
		_nmsg_payload_free_all(nmsg);
		reset_estsz(output->stream);
		goto out;
	}

	/* flush output if unbuffered */
	if (output->stream->buffered == false) {
		res = write_pbuf(output);
		_nmsg_payload_free_all(nmsg);
		reset_estsz(output->stream);

		/* sleep a bit if necessary */
		if (output->stream->rate != NULL)
			nmsg_rate_sleep(output->stream->rate);
	}

out:
	/* unlock output */
	pthread_mutex_unlock(&output->stream->lock);

	return (res);

error_out:
	/* unlock output */
	pthread_mutex_unlock(&output->stream->lock);

	/* give the payload back to the caller */
	msg->np = np;

	return (res);
}

void
_output_nmsg_header_serialize(struct nmsg_buf *buf, uint8_t flags) {
	char magic[] = NMSG_MAGIC;
	uint16_t vers;

	buf->pos = buf->data;
	memcpy(buf->pos, magic, sizeof(magic));
	buf->pos += sizeof(magic);
	vers = NMSG_VERSION | (flags << 8);
	vers = htons(vers);
	memcpy(buf->pos, &vers, sizeof(vers));
	buf->pos += sizeof(vers);
}

/* Private functions. */

static nmsg_res
write_pbuf(nmsg_output_t output) {
	Nmsg__Nmsg *nc;
	size_t len;
	uint8_t *len_wire;
	struct nmsg_buf *buf;

	buf = output->stream->buf;
	nc = output->stream->nmsg;
	_output_nmsg_header_serialize(buf, (output->stream->zb != NULL) ? NMSG_FLAG_ZLIB : 0);
	len_wire = buf->pos;
	buf->pos += sizeof(uint32_t);

	_nmsg_payload_calc_crcs(nc);

	if (output->type == nmsg_output_type_stream &&
	    output->stream->type == nmsg_stream_type_sock)
	{
		nc->has_sequence = true;
		nc->sequence = output->stream->sequence;
		output->stream->sequence += 1;

		nc->has_sequence_id = true;
		nc->sequence_id = output->stream->sequence_id;
	}

	if (output->stream->zb == NULL) {
		len = nmsg__nmsg__pack(nc, buf->pos);
	} else {
		nmsg_res res;
		size_t ulen;

		ulen = nmsg__nmsg__pack(nc, output->stream->zb_tmp);
		len = buf->bufsz;
		res = nmsg_zbuf_deflate(output->stream->zb, ulen,
					output->stream->zb_tmp, &len,
					buf->pos);
		if (res != nmsg_res_success)
			return (res);
	}
	store_net32(len_wire, len);
	buf->pos += len;
	return (write_output(output));
}

static nmsg_res
write_output(nmsg_output_t output) {
	ssize_t bytes_written;
	size_t len;
	struct nmsg_buf *buf;

	buf = output->stream->buf;

	len = _nmsg_buf_used(buf);
	assert(len <= buf->bufsz);

	if (output->stream->type == nmsg_stream_type_sock) {
		bytes_written = write(buf->fd, buf->data, len);
		if (bytes_written < 0) {
			perror("write");
			return (nmsg_res_failure);
		}
		assert((size_t) bytes_written == len);
	} else if (output->stream->type == nmsg_stream_type_file) {
		const u_char *ptr = buf->data;

		while (len) {
			bytes_written = write(buf->fd, ptr, len);
			if (bytes_written < 0 && errno == EINTR)
				continue;
			if (bytes_written < 0) {
				perror("write");
				return (nmsg_res_failure);
			}
			ptr += bytes_written;
			len -= bytes_written;
		}
	}
	return (nmsg_res_success);
}
