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

/* Internal functions. */

nmsg_res
_output_nmsg_flush(nmsg_output_t output) {
	nmsg_res res = nmsg_res_success;

	if (_nmsg_container_get_num_payloads(output->stream->c) > 0)
		res = _output_nmsg_write_container(output);

	return (res);
}

nmsg_res
_output_nmsg_write(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	nmsg_res res;

	assert(msg->np != NULL);
	np = msg->np;

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

	pthread_mutex_lock(&output->stream->lock);

	res = _nmsg_container_add(output->stream->c, msg);

	if (res == nmsg_res_container_full ||
	    (res == nmsg_res_success && output->stream->buffered == false))
	{
		res = _output_nmsg_write_container(output);
		if (res != nmsg_res_success)
			goto out;
		res = _nmsg_container_add(output->stream->c, msg);
		if (res == nmsg_res_container_overfull)
			res = _output_frag_write(output);
	} else if (res == nmsg_res_container_overfull) {
		res = _output_frag_write(output);
	}

out:
	pthread_mutex_unlock(&output->stream->lock);
	if (output->stream->rate != NULL)
		nmsg_rate_sleep(output->stream->rate);
	return (res);
}

nmsg_res
_output_nmsg_write_container(nmsg_output_t output) {
	nmsg_res res;
	size_t buf_len;
	uint8_t *buf;

	res = _nmsg_container_serialize(output->stream->c,
					&buf,
					&buf_len,
					true, /* do_header */
					output->stream->do_zlib,
					output->stream->sequence,
					output->stream->sequence_id
	);
	if (output->stream->do_sequence)
		output->stream->sequence += 1;

	if (res != nmsg_res_success)
		goto out;

	if (output->stream->type == nmsg_stream_type_sock) {
		res = _output_nmsg_write_sock(output, buf, buf_len);
	} else if (output->stream->type == nmsg_stream_type_file) {
		res = _output_nmsg_write_file(output, buf, buf_len);
	} else if (output->stream->type == nmsg_stream_type_zmq) {
		assert(0);
	}

out:
	free(buf);
	_nmsg_container_destroy(&output->stream->c);
	output->stream->c = _nmsg_container_init(output->stream->bufsz,
						 output->stream->do_sequence);
	if (output->stream->c == NULL)
		return (nmsg_res_memfail);
	return (res);
}

nmsg_res
_output_nmsg_write_sock(nmsg_output_t output, uint8_t *buf, size_t len) {
	ssize_t bytes_written;

	bytes_written = write(output->stream->fd, buf, len);
	if (bytes_written < 0) {
		perror("write");
		return (nmsg_res_failure);
	}
	assert((size_t) bytes_written == len);
	return (nmsg_res_success);
}

nmsg_res
_output_nmsg_write_file(nmsg_output_t output, uint8_t *buf, size_t len) {
	ssize_t bytes_written;
	const uint8_t *ptr = buf;

	while (len) {
		bytes_written = write(output->stream->fd, ptr, len);
		if (bytes_written < 0 && errno == EINTR)
			continue;
		if (bytes_written < 0) {
			perror("write");
			return (nmsg_res_failure);
		}
		ptr += bytes_written;
		len -= bytes_written;
	}
	return (nmsg_res_success);
}
