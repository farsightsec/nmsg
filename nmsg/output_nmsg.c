/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2008-2019 by Farsight Security, Inc.
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
static nmsg_res container_write(nmsg_output_t, nmsg_container_t*);
static nmsg_res frag_write(nmsg_output_t, nmsg_container_t);
static nmsg_res send_buffer(nmsg_output_t, uint8_t *buf, size_t len);

/* Internal functions. */

nmsg_res
_output_nmsg_flush(nmsg_output_t output) {
	nmsg_res res = nmsg_res_success;

	pthread_mutex_lock(&output->stream->c_lock);

	if (nmsg_container_get_num_payloads(output->stream->c) > 0) {

		/* Process container; container is destroyed. */
		res = container_write(output, &output->stream->c);

		output->stream->c = nmsg_container_init(output->stream->bufsz);
		if (output->stream->c == NULL)
			res = nmsg_res_memfail;
		else
			nmsg_container_set_sequence(output->stream->c, output->stream->do_sequence);

	}

	pthread_mutex_unlock(&output->stream->c_lock);

	return (res);
}

nmsg_res
_output_nmsg_write(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	struct nmsg_stream_output *ostr = output->stream;
	nmsg_container_t old_c, new_c;
	nmsg_res res;
	bool must_flush, is_buffered;

	assert(msg->np != NULL);
	np = msg->np;

	/* set source, output, group if necessary */
	if (ostr->source != 0) {
		np->source = ostr->source;
		np->has_source = 1;
	}
	if (ostr->operator != 0) {
		np->operator_ = ostr->operator;
		np->has_operator_ = 1;
	}
	if (ostr->group != 0) {
		np->group = ostr->group;
		np->has_group = 1;
	}

retry:
	must_flush = false;
	old_c = new_c = NULL;

	pthread_mutex_lock(&ostr->c_lock);	/* Lock for add to container. */

	/*
	 * Try to add the message to the current container. If the current
	 * container needs further processing (i.e. write/send its contents),
	 * then the current thread will:
	 *   1) Set up a new container for the stream.
	 *   2) Release container lock so other threads can use new container.
	 *   3) Proceed to further process the current container.
	 */
	res = nmsg_container_add(ostr->c, msg);

	/*
	 * If the processing block below is entered, first set up a new
	 * container for the other threads to use.
	 */
	is_buffered = ostr->buffered;	/* Save this value. */
	if ((res == nmsg_res_container_full) ||
	    (res == nmsg_res_success && is_buffered == false) ||
	    (res == nmsg_res_container_overfull)) {
		must_flush = true;	/* Will flush container below. */

		/* Create replacement container. */
		new_c = nmsg_container_init(ostr->bufsz);
		if (new_c == NULL) {
			pthread_mutex_unlock(&ostr->c_lock);
			return (nmsg_res_memfail);
		}

		nmsg_container_set_sequence(new_c, ostr->do_sequence);

		old_c = ostr->c;	/* Process old, proceed with new. */
		ostr->c = new_c;
	}

	pthread_mutex_unlock(&ostr->c_lock);	/* Release locked container to other threads. */

	if (!must_flush)			/* Nothing more to do here. */
		return (res);

	/* Reaching here WILL flush the prior container. */
	if (res == nmsg_res_container_full) {		/* Doesn't include current message. */
		res = container_write(output, &old_c);	/* Write data from prior container. */
		if (res != nmsg_res_success)
			return (res);

		/* Proceed to write current message to new container. */
		goto retry;
	} else if (res == nmsg_res_success && is_buffered == false) {	/* Includes current message. */
		res = container_write(output, &old_c);
	} else if (res == nmsg_res_container_overfull) {		/* Includes current message. */
		res = frag_write(output, old_c);
	}

	return (res);
}

/* Private functions. */

/*
 * Send/write the contents of a container.
 * Container is destroyed, whether contents are successfully processed or not.
 */
static nmsg_res
container_write(nmsg_output_t output, nmsg_container_t *co)
{
	nmsg_res res;
	size_t buf_len;
	uint32_t seq;
	uint8_t *buf;

	/* Multiple threads can enter here at once. */
	seq = atomic_fetch_add_explicit(&output->stream->so_sequence_num, 1, memory_order_relaxed);

	res = nmsg_container_serialize(*co, &buf, &buf_len, true, /* do_header */
					output->stream->do_zlib, seq, output->stream->sequence_id);

	if (res != nmsg_res_success)
		goto out;

	res = send_buffer(output, buf, buf_len);
out:
	nmsg_container_destroy(co);

	return (res);
}

static nmsg_res
write_sock(int fd, uint8_t *buf, size_t len)
{
	ssize_t bytes_written;

	bytes_written = write(fd, buf, len);
	if (bytes_written < 0) {
		_nmsg_dprintf(1, "%s: write() failed: %s\n", __func__, strerror(errno));
		free(buf);
		return (nmsg_res_errno);
	}
	free(buf);
	assert((size_t) bytes_written == len);
	return (nmsg_res_success);
}

#ifdef HAVE_LIBZMQ
static void
free_wrapper(void *ptr, void *hint __attribute__((unused)))
{
	free(ptr);
}

static nmsg_res
write_zmq(nmsg_output_t output, uint8_t *buf, size_t len)
{
	nmsg_res res = nmsg_res_success;
	zmq_msg_t zmsg;

	if (zmq_msg_init_data(&zmsg, buf, len, free_wrapper, NULL)) {
		free(buf);
		return (nmsg_res_failure);
	}

	for (;;) {
		int ret;
		zmq_pollitem_t zitems[1];
		zitems[0].socket = output->stream->zmq;
		zitems[0].events = ZMQ_POLLOUT;
		ret = zmq_poll(zitems, 1, NMSG_RBUF_TIMEOUT);
		if (ret > 0) {
			ret = zmq_sendmsg(output->stream->zmq, &zmsg, 0);
			if (ret > 0) {
				break;
			} else {
				res = nmsg_res_failure;
				_nmsg_dprintf(1, "%s: zmq_sendmsg() failed: %s\n",
					      __func__, strerror(errno));
				break;
			}
		}
		if (output->stop) {
			res = nmsg_res_stop;
			break;
		}
	}

	zmq_msg_close(&zmsg);
	return (res);
}
#endif /* HAVE_LIBZMQ */

static nmsg_res
write_file(int fd, uint8_t *buf, size_t len)
{
	ssize_t bytes_written;
	const uint8_t *ptr = buf;

	while (len) {
		bytes_written = write(fd, ptr, len);
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

/*
 * Send a buffer holding a serialized container to its destination.
 * The buffer will ALWAYS be free'd before this function returns.
 *
 * Returns status of send.
 */
static nmsg_res
send_buffer(nmsg_output_t output, uint8_t *buf, size_t len)
{
	struct nmsg_stream_output *ostr = output->stream;
	nmsg_res res;

	pthread_mutex_lock(&ostr->w_lock);

	if (ostr->type == nmsg_stream_type_sock) {
		res = write_sock(ostr->fd, buf, len);
	} else if (ostr->type == nmsg_stream_type_file) {
		res = write_file(ostr->fd, buf, len);
	} else if (ostr->type == nmsg_stream_type_zmq) {
#ifdef HAVE_LIBZMQ
		res = write_zmq(output, buf, len);
#else /* HAVE_LIBZMQ */
		assert(ostr->type != nmsg_stream_type_zmq);
#endif /* HAVE_LIBZMQ */
	} else if (ostr->type == nmsg_stream_type_kafka) {
#ifdef HAVE_LIBRDKAFKA
		res = kafka_write(output->stream->kafka, NULL, 0, buf, len);
#else /* HAVE_LIBRDKAFKA */
		assert(ostr->type != nmsg_stream_type_kafka);
#endif /* HAVE_LIBRDKAFKA */
	} else {
		assert(0);
	}

	/* Do "rate limit" delay (under lock). */
	if (ostr->rate != NULL)
		nmsg_rate_sleep(ostr->rate);

	pthread_mutex_unlock(&ostr->w_lock);

	return (res);
}

static void
header_serialize(uint8_t *buf, uint8_t flags, uint32_t len)
{
	static const char magic[] = NMSG_MAGIC;
	uint16_t version;

	memcpy(buf, magic, sizeof(magic));
	buf += sizeof(magic);

	version = NMSG_PROTOCOL_VERSION | (flags << 8);
	store_net16(buf, version);

	buf += sizeof(version);
	store_net32(buf, len);
}

static nmsg_res
frag_write(nmsg_output_t output, nmsg_container_t co)
{
	Nmsg__NmsgFragment nf;
	struct nmsg_stream_output *ostr = output->stream;
	unsigned i;
	nmsg_res res;
	size_t len, fragpos, fragsz, fraglen, max_fragsz;
	uint32_t seq;
	uint8_t flags = 0, *packed, *frag_packed, *frag_packed_container;

	assert(output->type == nmsg_output_type_stream);

#ifdef HAVE_LIBZMQ
	if (ostr->type == nmsg_stream_type_zmq) {
		/* let ZMQ do fragmentation instead */
		return (container_write(output, &co));
	}
#else /* HAVE_LIBZMQ */
	assert(ostr->type != nmsg_stream_type_zmq);
#endif /* HAVE_LIBZMQ */

	max_fragsz = ostr->bufsz - 32;

	/* Multiple threads can enter here at once. */
	seq = atomic_fetch_add_explicit(&ostr->so_sequence_num, 1, memory_order_relaxed);

	res = nmsg_container_serialize(co, &packed, &len, false, /* do_header */
				       ostr->do_zlib, seq, ostr->sequence_id);
	if (ostr->do_zlib)
		flags |= NMSG_FLAG_ZLIB;

	if (res != nmsg_res_success)
		return (res);

	if (ostr->do_zlib && len <= max_fragsz) {
		/* write out the unfragmented NMSG container */
		res = send_buffer(output, packed, len);
		goto frag_out;
	}

	/* create and send fragments */
	nmsg__nmsg_fragment__init(&nf);

	flags |= NMSG_FLAG_FRAGMENT;
	nf.id = nmsg_random_uint32(ostr->random);
	nf.last = len / max_fragsz;
	nf.crc = htonl(my_crc32c(packed, len));
	nf.has_crc = true;

	for (fragpos = 0, i = 0; fragpos < len; fragpos += max_fragsz, i++)
	{
		/* allocate a buffer large enough to hold one serialized fragment */
		frag_packed = malloc(NMSG_HDRLSZ_V2 + ostr->bufsz + 32);
		if (frag_packed == NULL) {
			free(packed);
			res = nmsg_res_memfail;
			goto frag_out;
		}
		frag_packed_container = frag_packed + NMSG_HDRLSZ_V2;

		/* serialize the fragment */
		nf.current = i;
		fragsz = (len - fragpos > max_fragsz) ? max_fragsz : (len - fragpos);
		nf.fragment.len = fragsz;
		nf.fragment.data = packed + fragpos;
		fraglen = nmsg__nmsg_fragment__pack(&nf, frag_packed_container);
		header_serialize(frag_packed, flags, fraglen);
		fraglen += NMSG_HDRLSZ_V2;

		/* send the serialized fragment */
		res = send_buffer(output, frag_packed, fraglen);
	}
	free(packed);

frag_out:
	nmsg_container_destroy(&co);

	return (res);
}
