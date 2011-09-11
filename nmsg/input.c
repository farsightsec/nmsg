/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#include "nmsg_port.h"
#include "nmsg_port_net.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "private.h"

/* Forward. */

static nmsg_input_t input_open_stream(nmsg_stream_type, int);
static nmsg_res input_flush(nmsg_input_t input);
static void input_close_stream(nmsg_input_t input);

static nmsg_res read_header(nmsg_input_t, ssize_t *);
static nmsg_res read_input(nmsg_input_t, ssize_t, ssize_t);
static nmsg_res read_input_oneshot(nmsg_input_t, ssize_t, ssize_t);

/* input_read.c */
static bool input_read_nmsg_filter(nmsg_input_t, Nmsg__NmsgPayload *);
static nmsg_res input_read_pcap(nmsg_input_t, nmsg_message_t *);
static nmsg_res input_read_pcap_raw(nmsg_input_t, nmsg_message_t *);
static nmsg_res input_read_pres(nmsg_input_t, nmsg_message_t *);
static nmsg_res input_read_nmsg(nmsg_input_t, nmsg_message_t *);
static nmsg_res input_read_nmsg_container(nmsg_input_t, Nmsg__Nmsg **);
static nmsg_res input_read_nmsg_loop(nmsg_input_t, int, nmsg_cb_message,
				     void *);

/* input_frag.c */
static nmsg_res read_input_frag(nmsg_input_t, ssize_t, Nmsg__Nmsg **);
static nmsg_res reassemble_frags(nmsg_input_t, Nmsg__Nmsg **,
				 struct nmsg_frag *);
static void free_frags(struct nmsg_stream_input *);
static void gc_frags(struct nmsg_stream_input *);

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
nmsg_input_open_pres(int fd, nmsg_msgmod_t msgmod) {
	nmsg_res res;
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_pres;
	input->read_fp = input_read_pres;

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
		input->read_fp = input_read_pcap_raw;
		nmsg_pcap_input_set_raw(pcap, true);
	} else if (msgmod->plugin->ipdg_to_payload != NULL) {
		input->read_fp = input_read_pcap;
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

/* Private. */

static nmsg_input_t
input_open_stream(nmsg_stream_type type, int fd) {
	struct nmsg_input *input;

	/* nmsg_input */
	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_stream;
	input->read_fp = input_read_nmsg;
	input->read_loop_fp = input_read_nmsg_loop;

	/* nmsg_stream_input */
	input->stream = calloc(1, sizeof(*(input->stream)));
	if (input->stream == NULL) {
		free(input);
		return (NULL);
	}
	input->stream->type = type;
	input->stream->blocking_io = true;

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

	/* red-black tree */
	RB_INIT(&input->stream->nft.head);

	return (input);
}

static void
input_close_stream(nmsg_input_t input) {
	if (input->stream->nmsg != NULL)
		input_flush(input);

	nmsg_zbuf_destroy(&input->stream->zb);
	free_frags(input->stream);
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

static nmsg_res
read_header(nmsg_input_t input, ssize_t *msgsize) {
	static char magic[] = NMSG_MAGIC;

	bool reset_buf = false;
	ssize_t bytes_avail, bytes_needed, lenhdrsz;
	nmsg_res res = nmsg_res_failure;
	uint16_t vers;
	struct nmsg_buf *buf;

	buf = input->stream->buf;

	/* initialize *msgsize */
	*msgsize = 0;

	/* ensure we have the (magic, version) header */
	bytes_avail = _nmsg_buf_avail(buf);
	if (bytes_avail < NMSG_HDRSZ) {
		if (input->stream->type == nmsg_stream_type_file) {
			assert(bytes_avail >= 0);
			bytes_needed = NMSG_HDRSZ - bytes_avail;
			if (bytes_avail == 0) {
				_nmsg_buf_reset(buf);
				res = read_input(input, bytes_needed, buf->bufsz);
			} else {
				/* the (magic, version) header was split */
				res = read_input(input, bytes_needed,
						 bytes_needed);
				reset_buf = true;
			}
		} else if (input->stream->type == nmsg_stream_type_sock) {
			assert(bytes_avail == 0);
			_nmsg_buf_reset(buf);
			res = read_input_oneshot(input, NMSG_HDRSZ, buf->bufsz);
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
	load_net16(buf->pos, &vers);
	buf->pos += 2;
	if (vers == 1U) {
		lenhdrsz = NMSG_LENHDRSZ_V1;
	} else if ((vers & 0xFF) == 2U) {
		input->stream->flags = vers >> 8;
		vers &= 0xFF;
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

	/* ensure we have the length header */
	bytes_avail = _nmsg_buf_avail(buf);
	if (bytes_avail < lenhdrsz) {
		if (bytes_avail == 0)
			_nmsg_buf_reset(buf);
		bytes_needed = lenhdrsz - bytes_avail;
		if (input->stream->type == nmsg_stream_type_file) {
			if (bytes_avail == 0) {
				res = read_input(input, bytes_needed,
						 buf->bufsz);
			} else {
				/* the length header was split */
				res = read_input(input, bytes_needed,
						 bytes_needed);
				reset_buf = true;
			}
		} else if (input->stream->type == nmsg_stream_type_sock) {
			/* the length header should have been read by
			 * read_input_oneshot() above */
			res = nmsg_res_failure;
			goto read_header_out;
		}
	}
	bytes_avail = _nmsg_buf_avail(buf);
	assert(bytes_avail >= lenhdrsz);

	/* load message size */
	if (vers == 1U) {
		load_net16(buf->pos, msgsize);
		buf->pos += 2;
	} else if (vers == 2U) {
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
read_input(nmsg_input_t input, ssize_t bytes_needed, ssize_t bytes_max) {
	ssize_t bytes_read;
	struct nmsg_buf *buf;

	buf = input->stream->buf;

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
read_input_oneshot(nmsg_input_t input, ssize_t bytes_needed, ssize_t bytes_max) {
	int ret;
	ssize_t bytes_read;
	struct nmsg_buf *buf;

	buf = input->stream->buf;

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
	bytes_read = read(buf->fd, buf->pos, bytes_max);
	if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return (nmsg_res_again);
	if (bytes_read < 0)
		return (nmsg_res_read_failure);
	if (bytes_read == 0)
		return (nmsg_res_eof);
	buf->end = buf->pos + bytes_read;
	assert(bytes_read >= bytes_needed);

	nmsg_timespec_get(&input->stream->now);
	return (nmsg_res_success);
}

#include "input_read.c"
#include "input_frag.c"
