/*
 * Copyright (c) 2008-2013 by Farsight Security, Inc.
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

#ifdef HAVE_LIBXS
static void free_wrapper(void *, void *);
#endif

/* Internal functions. */

nmsg_res
_output_nmsg_flush(nmsg_output_t output) {
	nmsg_res res = nmsg_res_success;

	pthread_mutex_lock(&output->stream->lock);
	if (nmsg_container_get_num_payloads(output->stream->c) > 0) {
		res = _output_nmsg_write_container(output);
		if (output->stream->rate != NULL)
			nmsg_rate_sleep(output->stream->rate);
	}
	pthread_mutex_unlock(&output->stream->lock);

	return (res);
}

nmsg_res
_output_nmsg_write(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	bool did_write = false;

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

	res = nmsg_container_add(output->stream->c, msg);

	if (res == nmsg_res_container_full) {
		res = _output_nmsg_write_container(output);
		if (res != nmsg_res_success)
			goto out;
		res = nmsg_container_add(output->stream->c, msg);
		if (res == nmsg_res_container_overfull)
			res = _output_frag_write(output);
		did_write = true;
	} else if (res == nmsg_res_success && output->stream->buffered == false) {
		res = _output_nmsg_write_container(output);
		did_write = true;
	} else if (res == nmsg_res_container_overfull) {
		res = _output_frag_write(output);
		did_write = true;
	}

out:
	if (did_write && output->stream->rate != NULL)
		nmsg_rate_sleep(output->stream->rate);
	pthread_mutex_unlock(&output->stream->lock);

	return (res);
}

nmsg_res
_output_nmsg_write_container(nmsg_output_t output) {
	nmsg_res res;
	size_t buf_len;
	uint8_t *buf;

	res = nmsg_container_serialize(output->stream->c,
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
	} else if (output->stream->type == nmsg_stream_type_xs) {
#ifdef HAVE_LIBXS
		res = _output_nmsg_write_xs(output, buf, buf_len);
#else /* HAVE_LIBXS */
		assert(output->stream->type != nmsg_stream_type_xs);
#endif /* HAVE_LIBXS */
	} else {
		assert(0);
	}

out:
	nmsg_container_destroy(&output->stream->c);
	output->stream->c = nmsg_container_init(output->stream->bufsz);
	if (output->stream->c == NULL)
		return (nmsg_res_memfail);
	nmsg_container_set_sequence(output->stream->c, output->stream->do_sequence);
	return (res);
}

nmsg_res
_output_nmsg_write_sock(nmsg_output_t output, uint8_t *buf, size_t len) {
	ssize_t bytes_written;

	bytes_written = write(output->stream->fd, buf, len);
	if (bytes_written < 0) {
		_nmsg_dprintf(1, "%s: write() failed: %s\n", __func__, strerror(errno));
		free(buf);
		return (nmsg_res_errno);
	}
	free(buf);
	assert((size_t) bytes_written == len);
	return (nmsg_res_success);
}

#ifdef HAVE_LIBXS
nmsg_res
_output_nmsg_write_xs(nmsg_output_t output, uint8_t *buf, size_t len) {
	nmsg_res res = nmsg_res_success;
	xs_msg_t xmsg;

	if (xs_msg_init_data(&xmsg, buf, len, free_wrapper, NULL)) {
		free(buf);
		return (nmsg_res_failure);
	}

	for (;;) {
		int ret;
		xs_pollitem_t xitems[1];
		xitems[0].socket = output->stream->xs;
		xitems[0].events = XS_POLLOUT;
		ret = xs_poll(xitems, 1, NMSG_RBUF_TIMEOUT);
		if (ret > 0) {
			ret = xs_sendmsg(output->stream->xs, &xmsg, 0);
			if (ret > 0) {
				break;
			} else {
				res = nmsg_res_failure;
				_nmsg_dprintf(1, "%s: xs_sendmsg() failed: %s\n",
					      __func__, strerror(errno));
				break;
			}
		}
		if (output->stop) {
			res = nmsg_res_stop;
			break;
		}
	}

	xs_msg_close(&xmsg);
	return (res);
}
#endif /* HAVE_LIBXS */

nmsg_res
_output_nmsg_write_file(nmsg_output_t output, uint8_t *buf, size_t len) {
	ssize_t bytes_written;
	const uint8_t *ptr = buf;

	while (len) {
		bytes_written = write(output->stream->fd, ptr, len);
		if (bytes_written < 0 && errno == EINTR)
			continue;
		if (bytes_written < 0) {
			_nmsg_dprintf(1, "%s: write() failed: %s\n", __func__, strerror(errno));
			free(buf);
			return (nmsg_res_errno);
		}
		ptr += bytes_written;
		len -= bytes_written;
	}
	free(buf);
	return (nmsg_res_success);
}

/* Private functions. */

#ifdef HAVE_LIBXS
static void
free_wrapper(void *ptr, void *hint __attribute__((unused))) {
	free(ptr);
}
#endif
