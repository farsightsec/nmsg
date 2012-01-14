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

nmsg_input_t
nmsg_input_open_zmq(void *s) {
	struct nmsg_input *input;

	input = input_open_stream_base(nmsg_stream_type_zmq);
	if (input == NULL)
		return (input);

	input->stream->zmq = s;

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
		res = msgmod->plugin->pcap_init(input->clos, input->pcap);
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
		input_close_stream(*input);
		break;
	case nmsg_input_type_pcap:
		nmsg_pcap_input_close(&(*input)->pcap);
		break;
	case nmsg_input_type_pres:
		fclose((*input)->pres->fp);
		free((*input)->pres);
		break;
	}

	if ((*input)->msgmod != NULL)
		nmsg_msgmod_fini((*input)->msgmod, &(*input)->clos);

	free(*input);
	*input = NULL;

	return (nmsg_res_success);
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

	/* nmsg_zbuf */
	input->stream->zb = nmsg_zbuf_inflate_init();
	if (input->stream->zb == NULL) {
		_nmsg_buf_destroy(&input->stream->buf);
		free(input->stream);
		free(input);
		return (NULL);
	}

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
	input->stream->type = type;
	if (type == nmsg_stream_type_file) {
		input->stream->stream_read_fp = _input_nmsg_read_container_file;
	} else if (type == nmsg_stream_type_sock) {
		input->stream->stream_read_fp = _input_nmsg_read_container_sock;
	} else if (type == nmsg_stream_type_zmq) {
		input->stream->stream_read_fp = _input_nmsg_read_container_zmq;
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
