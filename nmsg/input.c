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

static nmsg_input_t	input_open_stream(nmsg_stream_type, int);
static nmsg_input_t	input_open_stream_base(nmsg_stream_type);
static nmsg_res		input_flush(nmsg_input_t input);
static void		input_close_stream(nmsg_input_t input);

/* Export. */

nmsg_input_t
nmsg_input_open_file(int fd) {
	return (input_open_stream(nmsg_stream_type_file, fd));
}

nmsg_input_t
nmsg_input_open_sock(int fd) {
	return (input_open_stream(nmsg_stream_type_sock, fd));
}

#if (defined HAVE_LIBRDKAFKA) && (defined HAVE_JSON_C)
nmsg_input_t
nmsg_input_open_kafka_json(const char *address)
{
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);

	input->kafka = calloc(1, sizeof(*(input->kafka)));
	if (input->kafka == NULL) {
		free(input);
		return (NULL);
	}

	input->type = nmsg_input_type_kafka_json;
	input->read_fp = _input_kafka_json_read;

	input->kafka->ctx = kafka_create_consumer(address, NMSG_RBUF_TIMEOUT);
	if (input->kafka->ctx == NULL) {
		free(input->kafka);
		free(input);
		return (NULL);
	}

	return (input);
}
#else /* (defined HAVE_LIBRDKAFKA) && (defined HAVE_JSON_C) */
nmsg_input_t
nmsg_input_open_kafka_json(const char *address __attribute__((unused))) {
	return (NULL);
}
#endif /* (defined HAVE_LIBRDKAFKA) && (defined HAVE_JSON_C) */

#ifdef HAVE_LIBRDKAFKA
nmsg_input_t
_input_open_kafka(void *s) {
	struct nmsg_input *input;

	input = input_open_stream_base(nmsg_stream_type_kafka);
	if (input == NULL)
		return (input);

	input->stream->kafka = s;

	return (input);
}
#endif /* HAVE_LIBRDKAFKA */

#ifdef HAVE_LIBZMQ
nmsg_input_t
nmsg_input_open_zmq(void *s) {
	struct nmsg_input *input;

	input = input_open_stream_base(nmsg_stream_type_zmq);
	if (input == NULL)
		return (input);

	input->stream->zmq = s;

	return (input);
}
#else /* HAVE_LIBZMQ */
nmsg_input_t
nmsg_input_open_zmq(void *s __attribute__((unused))) {
	return (NULL);
}
#endif /* HAVE_LIBZMQ */

nmsg_input_t
nmsg_input_open_callback(nmsg_cb_message_read cb, void *user) {
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_callback;
	input->read_fp = _input_nmsg_read_callback;
	input->read_loop_fp = NULL;
	input->callback = calloc(1, sizeof(*(input->callback)));
	if (input->callback == NULL) {
		free(input);
		return (NULL);
	}
	input->callback->cb = cb;
	input->callback->user = user;

	return (input);
}

nmsg_input_t
nmsg_input_open_null(void) {
	struct nmsg_input *input;

	input = input_open_stream_base(nmsg_stream_type_null);
	if (input == NULL)
		return (NULL);
	input->read_fp = _input_nmsg_read_null;
	input->read_loop_fp = _input_nmsg_loop_null;

	return (input);
}

nmsg_input_t
nmsg_input_open_pres(int fd, nmsg_msgmod_t msgmod) {
	nmsg_res res;
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_pres;
	input->read_fp = _input_pres_read;

	input->pres = calloc(1, sizeof(*(input->pres)));
	if (input->pres == NULL) {
		free(input);
		return (NULL);
	}

	input->pres->fp = fdopen(fd, "r");
	if (input->pres->fp == NULL) {
		free(input->pres);
		free(input);
		return (NULL);
	}

	input->msgmod = msgmod;
	res = nmsg_msgmod_init(input->msgmod, &input->clos);
	if (res != nmsg_res_success) {
		fclose(input->pres->fp);
		free(input->pres);
		free(input);
		return (NULL);
	}

	return (input);
}

#ifdef HAVE_JSON_C
nmsg_input_t
nmsg_input_open_json(int fd) {
	struct nmsg_input *input;
	int newfd;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_json;
	input->read_fp = _input_json_read;

	input->json = calloc(1, sizeof(*(input->json)));
	if (input->json == NULL) {
		free(input);
		return (NULL);
	}

	input->json->orig_fd = fd;

	newfd = dup(fd);
	if (newfd == -1) {
		free(input->json);
		free(input);
		return (NULL);
	}

	input->json->fp = fdopen(newfd, "r");
	if (input->json->fp == NULL) {
		free(input->json);
		free(input);
		return (NULL);
	}

	return (input);
}
#else /* HAVE_JSON_C */
nmsg_input_t
nmsg_input_open_json(__attribute__((unused)) int fd) {
	return (NULL);
}
#endif /* HAVE_JSON_C */

nmsg_input_t
nmsg_input_open_pcap(nmsg_pcap_t pcap, nmsg_msgmod_t msgmod) {
	nmsg_res res;
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_pcap;
	input->pcap = pcap;

	if (msgmod->plugin->pkt_to_payload != NULL) {
		input->read_fp = _input_pcap_read_raw;
		nmsg_pcap_input_set_raw(pcap, true);
	} else if (msgmod->plugin->ipdg_to_payload != NULL) {
		input->read_fp = _input_pcap_read;
	} else {
		free(input);
		return (NULL);
	}

	input->msgmod = msgmod;
	res = nmsg_msgmod_init(input->msgmod, &input->clos);
	if (res != nmsg_res_success) {
		free(input);
		return (NULL);
	}
	if (msgmod->plugin->pcap_init != NULL) {
		void *clos = input->clos;
		if (msgmod->plugin->type == nmsg_msgmod_type_transparent)
			clos = ((struct nmsg_msgmod_clos *) clos)->mod_clos;
		res = msgmod->plugin->pcap_init(clos, input->pcap);
		if (res != nmsg_res_success) {
			free(input);
			return (NULL);
		}
	}

	return (input);
}

nmsg_res
nmsg_input_close(nmsg_input_t *input) {
	switch ((*input)->type) {
	case nmsg_input_type_stream:
		_nmsg_brate_destroy(&((*input)->stream->brate));
#ifdef HAVE_LIBRDKAFKA
		if ((*input)->stream->type == nmsg_stream_type_kafka)
			kafka_ctx_destroy(&(*input)->stream->kafka);
#else /* HAVE_LIBRDKAFKA */
		assert((*input)->stream->type != nmsg_stream_type_kafka);
#endif /* HAVE_LIBRDKAFKA */
#ifdef HAVE_LIBZMQ
		if ((*input)->stream->type == nmsg_stream_type_zmq)
			zmq_close((*input)->stream->zmq);
#else /* HAVE_LIBZMQ */
		assert((*input)->stream->type != nmsg_stream_type_zmq);
#endif /* HAVE_LIBZMQ */
		input_close_stream(*input);
		break;
	case nmsg_input_type_pcap:
		nmsg_pcap_input_close(&(*input)->pcap);
		break;
	case nmsg_input_type_pres:
		fclose((*input)->pres->fp);
		free((*input)->pres);
		break;
	case nmsg_input_type_json:
		if (_nmsg_global_autoclose)
			close((*input)->json->orig_fd);
		fclose((*input)->json->fp);
		free((*input)->json);
		break;
	case nmsg_input_type_kafka_json:
#ifdef HAVE_LIBRDKAFKA
		kafka_ctx_destroy(&(*input)->kafka->ctx);
		free((*input)->kafka);
#endif /* HAVE_LIBRDKAFKA */
		break;
	case nmsg_input_type_callback:
		free((*input)->callback);
		break;
	}

	if ((*input)->msgmod != NULL)
		nmsg_msgmod_fini((*input)->msgmod, &(*input)->clos);

	free(*input);
	*input = NULL;

	return (nmsg_res_success);
}

void
nmsg_input_breakloop(nmsg_input_t input) {
	input->stop = true;
}

nmsg_res
nmsg_input_read(nmsg_input_t input, nmsg_message_t *msg) {
	return (input->read_fp(input, msg));
}

nmsg_res
nmsg_input_loop(nmsg_input_t input, int cnt, nmsg_cb_message cb, void *user) {
	int n_payloads = 0;
	nmsg_message_t msg;
	nmsg_res res;

	if (input->read_loop_fp != NULL)
		return (input->read_loop_fp(input, cnt, cb, user));

	for (;;) {
		res = input->read_fp(input, &msg);
		if (res == nmsg_res_again)
			continue;
		if (res != nmsg_res_success)
			return (res);

		if (cnt >= 0 && n_payloads == cnt)
			break;
		if (input->stop)
			break;
		n_payloads += 1;
		cb(msg, user);
	}

	return (nmsg_res_success);
}

void
nmsg_input_set_filter_msgtype(nmsg_input_t input,
			      unsigned vid, unsigned msgtype)
{
	if (vid == 0 && msgtype == 0)
		input->do_filter = false;
	else
		input->do_filter = true;

	input->filter_vid = vid;
	input->filter_msgtype = msgtype;
}

nmsg_res
nmsg_input_set_filter_msgtype_byname(nmsg_input_t input,
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

	nmsg_input_set_filter_msgtype(input, vid, msgtype);

	return (nmsg_res_success);
}

void
nmsg_input_set_filter_source(nmsg_input_t input, unsigned source) {
	if (input->type == nmsg_input_type_stream)
		input->stream->source = source;
}

void
nmsg_input_set_filter_operator(nmsg_input_t input, unsigned operator) {
	if (input->type == nmsg_input_type_stream)
		input->stream->operator = operator;
}

void
nmsg_input_set_filter_group(nmsg_input_t input, unsigned group) {
	if (input->type == nmsg_input_type_stream)
		input->stream->group = group;
}

nmsg_res
nmsg_input_set_blocking_io(nmsg_input_t input, bool flag) {
	int val;

	if (input->type != nmsg_input_type_stream)
		return (nmsg_res_failure);

	if ((val = fcntl(input->stream->buf->fd, F_GETFL, 0)) < 0)
		return (nmsg_res_failure);

	if (flag == true)
		val &= ~O_NONBLOCK;
	else
		val |= O_NONBLOCK;

	if (fcntl(input->stream->buf->fd, F_SETFL, val) < 0)
		return (nmsg_res_failure);

	if (flag == true)
		input->stream->blocking_io = true;
	else
		input->stream->blocking_io = false;

	return (nmsg_res_success);
}

nmsg_res
nmsg_input_set_byte_rate(nmsg_input_t input, size_t target_byte_rate) {
	if (input->type != nmsg_input_type_stream)
		return (nmsg_res_failure);
	if (input->stream->brate != NULL)
		_nmsg_brate_destroy(&input->stream->brate);
	if (target_byte_rate > 0) {
		input->stream->brate = _nmsg_brate_init(target_byte_rate);
		if (input->stream->brate == NULL)
			return (nmsg_res_failure);
	}
	return (nmsg_res_success);
}

nmsg_res
nmsg_input_set_verify_seqsrc(nmsg_input_t input, bool verify) {
	if (input->type != nmsg_input_type_stream)
		return (nmsg_res_failure);
	input->stream->verify_seqsrc = verify;
	return (nmsg_res_success);
}

nmsg_res
nmsg_input_get_count_container_received(nmsg_input_t input, uint64_t *count) {
	if (input->type == nmsg_input_type_stream) {
		*count = input->stream->count_recv;
		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

nmsg_res
nmsg_input_get_count_container_dropped(nmsg_input_t input, uint64_t *count) {
	if (input->type == nmsg_input_type_stream &&
	    input->stream->verify_seqsrc)
	{
		*count = input->stream->count_drop;
		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

/* Private functions. */

static nmsg_input_t
input_open_stream(nmsg_stream_type type, int fd) {
	struct nmsg_input *input;

	input = input_open_stream_base(type);
	if (input == NULL)
		return (input);

	/* nmsg_buf */
	input->stream->buf = _nmsg_buf_new(NMSG_RBUFSZ);
	if (input->stream->buf == NULL) {
		free(input->stream);
		free(input);
		return (NULL);
	}
	_nmsg_buf_reset(input->stream->buf);
	input->stream->buf->fd = fd;
	input->stream->buf->bufsz = NMSG_RBUFSZ / 2;

	/* struct pollfd */
	input->stream->pfd.fd = fd;
	input->stream->pfd.events = POLLIN;

	return (input);
}

static nmsg_input_t
input_open_stream_base(nmsg_stream_type type) {
	struct nmsg_input *input;

	/* nmsg_input */
	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_stream;
	input->read_fp = _input_nmsg_read;
	input->read_loop_fp = _input_nmsg_loop;

	/* nmsg_stream_input */
	input->stream = calloc(1, sizeof(*(input->stream)));
	if (input->stream == NULL) {
		free(input);
		return (NULL);
	}
	input->stream->blocking_io = true;
	input->stream->verify_seqsrc = true;
	input->stream->type = type;
	if (type == nmsg_stream_type_file) {
		input->stream->stream_read_fp = _input_nmsg_read_container_file;
	} else if (type == nmsg_stream_type_sock) {
		input->stream->stream_read_fp = _input_nmsg_read_container_sock;
	} else if (type == nmsg_stream_type_zmq) {
#ifdef HAVE_LIBZMQ
		input->stream->stream_read_fp = _input_nmsg_read_container_zmq;
#else /* HAVE_LIBZMQ */
		assert(type != nmsg_stream_type_zmq);
#endif /* HAVE_LIBZMQ */
	} else if (type == nmsg_stream_type_kafka) {
#ifdef HAVE_LIBRDKAFKA
		input->stream->stream_read_fp = _input_nmsg_read_container_kafka;
#else /* HAVE_LIBRDKAFKA */
		assert(type != nmsg_stream_type_kafka);
#endif /* HAVE_LIBRDKAFKA */
	}

	/* nmsg_zbuf */
	input->stream->zb = nmsg_zbuf_inflate_init();
	if (input->stream->zb == NULL) {
		_nmsg_buf_destroy(&input->stream->buf);
		free(input->stream);
		free(input);
		return (NULL);
	}

	/* red-black tree */
	RB_INIT(&input->stream->nft.head);

	/* nmsg seqsrc */
	ISC_LIST_INIT(input->stream->seqsrcs);

	return (input);
}

static void
input_close_stream(nmsg_input_t input) {
	_input_seqsrc_destroy(input);

	if (input->stream->nmsg != NULL)
		input_flush(input);

	nmsg_zbuf_destroy(&input->stream->zb);
	_input_frag_destroy(input->stream);
	_nmsg_buf_destroy(&input->stream->buf);
	free(input->stream);
}

static nmsg_res
input_flush(nmsg_input_t input) {
	if (input->type == nmsg_input_type_stream) {
		Nmsg__Nmsg *nmsg;
		unsigned i;

		nmsg = input->stream->nmsg;
		assert(nmsg != NULL);

		for (i = 0; i < nmsg->n_payloads; i++)
			if (nmsg->payloads[i] != NULL)
				_nmsg_payload_free(&nmsg->payloads[i]);
		nmsg->n_payloads = 0;
		nmsg__nmsg__free_unpacked(nmsg, NULL);
	}

	return (nmsg_res_success);
}
