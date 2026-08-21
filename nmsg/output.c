/*
 * Copyright (c) 2023-2024 DomainTools LLC
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

static nmsg_output_t	output_open_stream(nmsg_stream_type, int, size_t);
static nmsg_output_t	output_open_stream_base(nmsg_stream_type, size_t);
static nmsg_res		output_write_callback(nmsg_output_t, nmsg_message_t);

/* Export. */

nmsg_output_t
nmsg_output_open_file(int fd, size_t bufsz) {
	return (output_open_stream(nmsg_stream_type_file, fd, bufsz));
}

nmsg_output_t
nmsg_output_open_sock(int fd, size_t bufsz) {
	return (output_open_stream(nmsg_stream_type_sock, fd, bufsz));
}

#ifdef HAVE_LIBRDKAFKA
nmsg_output_t
nmsg_output_open_kafka_json(const char *addr, const char *key_field)
{
	struct nmsg_output *output;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);

	output->kafka = calloc(1, sizeof(*(output->kafka)));
	if (output->kafka == NULL) {
		free(output);
		return (NULL);
	}

	output->type = nmsg_output_type_kafka_json;
	output->write_fp = _output_kafka_json_write;
	output->flush_fp = _output_kafka_json_flush;

	output->kafka->ctx = kafka_create_producer(addr, NMSG_RBUF_TIMEOUT);
	if (!output->kafka->ctx) {
		free(output->kafka);
		free(output);
		return NULL;
	}

	if (key_field != NULL) {
		output->kafka->key_field = strdup(key_field);
		if (output->kafka->key_field == NULL) {
			kafka_ctx_destroy(&output->kafka->ctx);
			free(output->kafka);
			free(output);
			return (NULL);
		}
	}

	return output;
};
#else /* HAVE_LIBRDKAFKA */
nmsg_output_t
nmsg_output_open_kafka_json(const char *addr __attribute__((unused)),
			    const char *key_field __attribute__((unused)))
{
	return (NULL);
}
#endif /* HAVE_LIBRDKAFKA */

#ifdef HAVE_LIBRDKAFKA
nmsg_output_t
nmsg_output_open_kafka_payload(const char *addr, const char *key_field)
{
	struct nmsg_output *output;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);

	output->kafka = calloc(1, sizeof(*(output->kafka)));
	if (output->kafka == NULL) {
		free(output);
		return (NULL);
	}

	output->type     = nmsg_output_type_kafka_payload;
	output->write_fp = _output_kafka_payload_write;
	output->flush_fp = _output_kafka_payload_flush;

	output->kafka->ctx = kafka_create_producer(addr, NMSG_RBUF_TIMEOUT);
	if (!output->kafka->ctx) {
		free(output->kafka);
		free(output);
		return (NULL);
	}

	if (key_field != NULL)
		output->kafka->key_field = strdup(key_field);

	return output;
}
#else /* HAVE_LIBRDKAFKA */
nmsg_output_t
nmsg_output_open_kafka_payload(const char *addr __attribute__((unused)),
			       const char *key_field __attribute__((unused)))
{
	return (NULL);
}
#endif /* HAVE_LIBRDKAFKA */

#ifdef HAVE_LIBRDKAFKA
nmsg_output_t
_output_open_kafka(void *s, size_t bufsz) {
	struct nmsg_output *output;

	output = output_open_stream_base(nmsg_stream_type_kafka, bufsz);
	if (output == NULL)
		return (output);

	output->stream->kafka = s;

	return (output);
}
#endif /* HAVE_LIBRDKAFKA */

#ifdef HAVE_LIBZMQ
nmsg_output_t
nmsg_output_open_zmq(void *s, size_t bufsz) {
	struct nmsg_output *output;

	output = output_open_stream_base(nmsg_stream_type_zmq, bufsz);
	if (output == NULL)
		return (output);

	output->stream->zmq = s;

	return (output);
}
#else /* HAVE_LIBZMQ */
nmsg_output_t
nmsg_output_open_zmq(void *s __attribute__((unused)),
		     size_t bufsz __attribute__((unused)))
{
	return (NULL);
}
#endif /* HAVE_LIBZMQ */

nmsg_output_t
nmsg_output_open_pres(int fd) {
	struct nmsg_output *output;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_pres;
	output->write_fp = _output_pres_write;

	output->pres = calloc(1, sizeof(*(output->pres)));
	if (output->pres == NULL) {
		free(output);
		return (NULL);
	}
	output->pres->fp = fdopen(fd, "w");
	if (output->pres->fp == NULL) {
		free(output->pres);
		free(output);
		return (NULL);
	}
	output->pres->endline = strdup("\n");
	if (output->pres->endline == NULL) {
		fclose(output->pres->fp);
		free(output->pres);
		free(output);
		return (NULL);
	}
	pthread_mutex_init(&output->pres->lock, NULL);

	return (output);
}

nmsg_output_t
nmsg_output_open_json(int fd) {
	struct nmsg_output *output;
	int newfd;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_json;
	output->write_fp = _output_json_write;

	output->json = calloc(1, sizeof(*(output->json)));
	if (output->json == NULL) {
		free(output);
		return (NULL);
	}

	output->json->orig_fd = fd;

	newfd = dup(fd);
	if (newfd == -1) {
		free(output->json);
		free(output);
		return (NULL);
	}

	output->json->fp = fdopen(newfd, "w");
	if (output->json->fp == NULL) {
		free(output->json);
		free(output);
		return (NULL);
	}
	pthread_mutex_init(&output->json->lock, NULL);

	return (output);
}

nmsg_output_t
nmsg_output_open_callback(nmsg_cb_message cb, void *user) {
	struct nmsg_output *output;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_callback;
	output->write_fp = output_write_callback;

	output->callback = calloc(1, sizeof(*(output->callback)));
	if (output->callback == NULL) {
		free(output);
		return (NULL);
	}
	output->callback->cb = cb;
	output->callback->user = user;

	return (output);
}

nmsg_res
nmsg_output_flush(nmsg_output_t output) {
	return (output->flush_fp(output));
}

nmsg_res
nmsg_output_write(nmsg_output_t output, nmsg_message_t msg) {
	nmsg_res res;

	res = _nmsg_message_serialize(msg);
	if (res != nmsg_res_success)
		return (res);

	if (output->do_filter == true &&
	    (output->filter_vid != msg->np->vid ||
	     output->filter_msgtype != msg->np->msgtype))
	{
		return (nmsg_res_success);
	}

	res = output->write_fp(output, msg);
	return (res);
}

nmsg_res
nmsg_output_close(nmsg_output_t *output) {
	nmsg_res res, async_res;

	res = nmsg_res_success;
	switch ((*output)->type) {
	case nmsg_output_type_stream:
		res = _output_nmsg_flush(*output);

		/*
		 * Before random, fd and the locks below, all of which the
		 * compressor thread uses.
		 */
		async_res = _output_async_destroy(*output);
		if (res == nmsg_res_success)
			res = async_res;

		if ((*output)->stream->random != NULL)
			nmsg_random_destroy(&((*output)->stream->random));
#ifdef HAVE_LIBRDKAFKA
		if ((*output)->stream->type == nmsg_stream_type_kafka)
			kafka_ctx_destroy(&(*output)->stream->kafka);
#else /* HAVE_LIBRDKAFKA */
		assert((*output)->stream->type != nmsg_stream_type_kafka);
#endif /* HAVE_LIBRDKAFKA */
#ifdef HAVE_LIBZMQ
		if ((*output)->stream->type == nmsg_stream_type_zmq)
			zmq_close((*output)->stream->zmq);
#else /* HAVE_LIBZMQ */
		assert((*output)->stream->type != nmsg_stream_type_zmq);
#endif /* HAVE_LIBZMQ */
		if ((*output)->stream->type == nmsg_stream_type_file ||
		    (*output)->stream->type == nmsg_stream_type_sock)
		{
			if (_nmsg_global_autoclose)
				close((*output)->stream->fd);
		}
		nmsg_container_destroy(&(*output)->stream->c);
		pthread_cond_destroy(&(*output)->stream->c_drained);
		pthread_mutex_destroy(&(*output)->stream->c_lock);
		pthread_mutex_destroy(&(*output)->stream->w_lock);
		free((*output)->stream);
		break;
	case nmsg_output_type_pres:
		fclose((*output)->pres->fp);
		free((*output)->pres->endline);
		free((*output)->pres);
		break;
	case nmsg_output_type_json:
		if (_nmsg_global_autoclose)
			close((*output)->json->orig_fd);
		fclose((*output)->json->fp);
		free((*output)->json);
		break;
	case nmsg_output_type_kafka_json:
	case nmsg_output_type_kafka_payload:
#ifdef HAVE_LIBRDKAFKA
		kafka_ctx_destroy(&(*output)->kafka->ctx);
		if ((*output)->kafka->key_field != NULL)
			free((void *) (*output)->kafka->key_field);
		free((*output)->kafka);
#else /* HAVE_LIBRDKAFKA */
		assert((*output)->type != nmsg_output_type_kafka_json);
		assert((*output)->type != nmsg_output_type_kafka_payload);
#endif /* HAVE_LIBRDKAFKA */
		break;
	case nmsg_output_type_callback:
		free((*output)->callback);
		break;
	}
	free(*output);
	*output = NULL;
	return (res);
}

void
nmsg_output_set_buffered(nmsg_output_t output, bool buffered) {
	switch(output->type) {
	case nmsg_output_type_stream:
		output->stream->buffered = buffered;
		break;
	case nmsg_output_type_pres:
		output->pres->flush = !(buffered);
		break;
	case nmsg_output_type_json:
		output->json->flush = !(buffered);
	case nmsg_output_type_kafka_json:
	default:
		break;
	}
}

void
nmsg_output_set_filter_msgtype(nmsg_output_t output, unsigned vid, unsigned msgtype) {
	if (vid == 0 && msgtype == 0)
		output->do_filter = false;
	else
		output->do_filter = true;

	output->filter_vid = vid;
	output->filter_msgtype = msgtype;
}

nmsg_res
nmsg_output_set_filter_msgtype_byname(nmsg_output_t output,
				      const char *vname, const char *mname)
{
	unsigned vid, msgtype;

	if (vname == NULL || mname == NULL)
		return (nmsg_res_failure);

	vid = nmsg_msgmod_vname_to_vid(vname);
	if (vid == 0)
		return (nmsg_res_failure);
	msgtype = nmsg_msgmod_mname_to_msgtype(vid, mname);
	if (msgtype == 0)
		return (nmsg_res_failure);

	nmsg_output_set_filter_msgtype(output, vid, msgtype);

	return (nmsg_res_success);
}

void
nmsg_output_set_rate(nmsg_output_t output, nmsg_rate_t rate) {
	if (output->type != nmsg_output_type_stream)
		return;

	pthread_mutex_lock(&output->stream->w_lock);
	output->stream->rate = rate;
	pthread_mutex_unlock(&output->stream->w_lock);
}

void
nmsg_output_set_zlibout(nmsg_output_t output, bool zlibout) {
	if (output->type != nmsg_output_type_stream)
		return;
	output->stream->do_zlib = zlibout;
}

nmsg_res
nmsg_output_set_zlib_workers(nmsg_output_t output, unsigned workers)
{
	/*
	 * Type test first: 'stream' is a union member, so reading stream->type
	 * on a pres or json output would reinterpret another struct's bytes.
	 */
	if (output->type != nmsg_output_type_stream)
		return (nmsg_res_success);
	if (output->stream->type != nmsg_stream_type_file)
		return (nmsg_res_success);

	/*
	 * Unbuffered flushes a container per message, so a pool would spend a
	 * ticket and a wakeup per message to compress a single payload.
	 */
	if (workers > 0 && !output->stream->buffered)
		return (nmsg_res_failure);

	if (workers > 0)
		return (_output_async_init(output, workers));

	/* Turning a pool off can strand an error a worker recorded. */
	return (_output_async_destroy(output));
}

void
nmsg_output_set_zlib_cull(nmsg_output_t output, unsigned min_workers,
			  unsigned idle_secs)
{
	struct nmsg_stream_output *ostr;
	struct nmsg_ostr_async *pool;

	/* Type test first, for the reason nmsg_output_set_zlib_workers() gives. */
	if (output->type != nmsg_output_type_stream)
		return;
	if (output->stream->type != nmsg_stream_type_file)
		return;

	ostr = output->stream;

	/*
	 * Kept on the stream, not just in the pool: a ceiling change replaces
	 * the pool, and this way the two setters may be called in any order.
	 * Nothing is logged when there is no pool -- nmsgtool sets a policy on
	 * every output, so it would fire on a plain '--unbuffered -w'.
	 */
	pthread_mutex_lock(&ostr->c_lock);
	ostr->so_zmin = min_workers;
	ostr->so_zcull = idle_secs;

	/*
	 * Taken under c_lock so a teardown cannot free the pool underneath.
	 * Lock order is c_lock then pool->lock; nothing takes them the other way.
	 */
	pool = _output_async_ref(ostr);
	pthread_mutex_unlock(&ostr->c_lock);

	if (pool != NULL) {
		_output_async_set_cull(pool, min_workers, idle_secs);
		_output_async_unref(ostr);
	}
}

void
nmsg_output_set_endline(nmsg_output_t output, const char *endline) {
	if (output->type == nmsg_output_type_pres) {
		char *ptr = strdup(endline);
		if (ptr != NULL) {
			free(output->pres->endline);
			output->pres->endline = ptr;
		}
	}
}

void
nmsg_output_set_source(nmsg_output_t output, unsigned source) {
	switch(output->type) {
	case nmsg_output_type_stream:
		output->stream->source = source;
		break;
	case nmsg_output_type_pres:
		output->pres->source = source;
		break;
	case nmsg_output_type_json:
		output->json->source = source;
		break;
	case nmsg_output_type_kafka_json:
	case nmsg_output_type_kafka_payload:
		output->kafka->source = source;
	default:
		break;
	}
}

void
nmsg_output_set_operator(nmsg_output_t output, unsigned operator) {
	switch(output->type) {
	case nmsg_output_type_stream:
		output->stream->operator = operator;
		break;
	case nmsg_output_type_pres:
		output->pres->operator = operator;
		break;
	case nmsg_output_type_json:
		output->json->operator = operator;
		break;
	case nmsg_output_type_kafka_json:
	case nmsg_output_type_kafka_payload:
		output->kafka->operator = operator;
	default:
		break;
	}
}

void
nmsg_output_set_group(nmsg_output_t output, unsigned group) {
	switch(output->type) {
	case nmsg_output_type_stream:
		output->stream->group = group;
		break;
	case nmsg_output_type_pres:
		output->pres->group = group;
		break;
	case nmsg_output_type_json:
		output->json->group = group;
		break;
	case nmsg_output_type_kafka_json:
	case nmsg_output_type_kafka_payload:
		output->kafka->group = group;
	default:
		break;
	}
}

void
_output_stop(nmsg_output_t output) {
	output->stop = true;
#ifdef HAVE_LIBRDKAFKA
	if (output->type == nmsg_output_type_kafka_json)
		kafka_stop(output->kafka->ctx);
	if (output->type == nmsg_output_type_kafka_payload)
		kafka_stop(output->kafka->ctx);
	else if (output->type == nmsg_output_type_stream &&
	    output->stream != NULL &&
	    output->stream->type == nmsg_stream_type_kafka)
		kafka_stop(output->stream->kafka);
#endif /* HAVE_LIBRDKAFKA */
}

/* Private functions. */

static nmsg_output_t
output_open_stream(nmsg_stream_type type, int fd, size_t bufsz) {
	struct nmsg_output *output;

	output = output_open_stream_base(type, bufsz);
	if (output == NULL)
		return (output);

	/* fd */
	if (type == nmsg_stream_type_file ||
	    type == nmsg_stream_type_sock)
	{
		output->stream->fd = fd;
	}

	return (output);
}

static nmsg_output_t
output_open_stream_base(nmsg_stream_type type, size_t bufsz) {
	struct nmsg_output *output;

	/* nmsg_output */
	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_stream;
	output->write_fp = _output_nmsg_write;
	output->flush_fp = _output_nmsg_flush;

	/* nmsg_stream_output */
	output->stream = calloc(1, sizeof(*(output->stream)));
	if (output->stream == NULL) {
		free(output);
		return (NULL);
	}
	output->stream->type = type;
	output->stream->buffered = true;
	output->stream->so_zmin = NMSG_ZCULL_MIN_WORKERS_DEFAULT;
	output->stream->so_zcull = NMSG_ZCULL_SECS_DEFAULT;

	/* seed the rng, needed for fragment and sequence IDs */
	output->stream->random = nmsg_random_init();
	if (output->stream->random == NULL) {
		free(output->stream);
		free(output);
		return (NULL);
	}

	pthread_mutex_init(&output->stream->c_lock, NULL);
	pthread_mutex_init(&output->stream->w_lock, NULL);
	if (pthread_cond_init(&output->stream->c_drained, NULL) != 0) {
		nmsg_random_destroy(&output->stream->random);
		pthread_mutex_destroy(&output->stream->c_lock);
		pthread_mutex_destroy(&output->stream->w_lock);
		free(output->stream);
		free(output);
		return (NULL);
	}

	/*
	 * Enable container sequencing. Sock and zmq only, which is what lets
	 * the async compressor number containers in compression order;
	 * widening this test needs _output_nmsg_container_compress() looked
	 * at.
	 */
	if (output->stream->type == nmsg_stream_type_sock ||
	    output->stream->type == nmsg_stream_type_zmq)
	{
		output->stream->do_sequence = true;

		/* generate sequence ID */
		nmsg_random_buf(output->stream->random,
				(uint8_t *) &output->stream->sequence_id,
				sizeof(output->stream->sequence_id));
	}

	/* bufsz */
	if (bufsz < NMSG_WBUFSZ_MIN)
		bufsz = NMSG_WBUFSZ_MIN;
	if (bufsz > NMSG_WBUFSZ_MAX)
		bufsz = NMSG_WBUFSZ_MAX;
	output->stream->bufsz = bufsz;

	/* nmsg container */
	output->stream->c = nmsg_container_init(bufsz);
	if (output->stream->c == NULL) {
		nmsg_random_destroy(&output->stream->random);
		pthread_cond_destroy(&output->stream->c_drained);
		pthread_mutex_destroy(&output->stream->c_lock);
		pthread_mutex_destroy(&output->stream->w_lock);
		free(output->stream);
		free(output);
		return (NULL);
	}
	nmsg_container_set_sequence(output->stream->c, output->stream->do_sequence);

	return (output);
}

static nmsg_res
output_write_callback(nmsg_output_t output, nmsg_message_t msg) {
	output->callback->cb(msg, output->callback->user);
	return (nmsg_res_success);
}
