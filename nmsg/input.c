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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "private.h"

/* Forward. */

static nmsg_input_t input_open_stream(nmsg_stream_type, int);
static nmsg_res read_header(nmsg_input_t, ssize_t *);
static nmsg_res read_input(nmsg_input_t, ssize_t, ssize_t);
static nmsg_res read_input_oneshot(nmsg_input_t, ssize_t, ssize_t);
static nmsg_res read_input_container(nmsg_input_t, Nmsg__Nmsg **);
static void input_close_stream(nmsg_input_t input);

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
nmsg_input_open_pres(int fd, nmsg_pbmod_t pbmod) {
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_pres;

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

	input->pres->pbmod = pbmod;

	return (input);
}

nmsg_input_t
nmsg_input_open_pcap(nmsg_pcap_t pcap, nmsg_pbmod_t pbmod) {
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_pcap;
	input->pcap = pcap;
	input->pcap->pbmod = pbmod;

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
	free(*input);
	*input = NULL;
	return (nmsg_res_success);
}

static void
input_close_stream(nmsg_input_t input) {
	if (input->stream->nmsg != NULL)
		nmsg_input_flush(input);

	nmsg_zbuf_destroy(&input->stream->zb);
	free_frags(input->stream);
	nmsg_buf_destroy(&input->stream->buf);
	free(input->stream);
}

nmsg_res
nmsg_input_next(nmsg_input_t input, Nmsg__NmsgPayload **np) {
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
		res = read_input_container(input, &input->stream->nmsg);
		if (res != nmsg_res_success)
			return (res);
		input->stream->np_index = 0;
	}

	/* pass a pointer to the payload to the caller */
	*np = input->stream->nmsg->payloads[input->stream->np_index];

	/* detach the payload from the original nmsg container */
	input->stream->nmsg->payloads[input->stream->np_index] = NULL;

	return (nmsg_res_success);
}

nmsg_res
nmsg_input_flush(nmsg_input_t input) {
	Nmsg__Nmsg *nmsg;
	unsigned i;

	nmsg = input->stream->nmsg;
	assert(nmsg != NULL);

	for (i = 0; i < nmsg->n_payloads; i++)
		if (nmsg->payloads[i] != NULL)
			nmsg_payload_free(&nmsg->payloads[i]);
	nmsg->n_payloads = 0;
	nmsg__nmsg__free_unpacked(nmsg, NULL);

	return (nmsg_res_success);
}

nmsg_res
nmsg_input_loop(nmsg_input_t input, int cnt, nmsg_cb_payload cb, void *user) {
	int i;
	unsigned n;
	nmsg_res res;
	Nmsg__Nmsg *nmsg;

	if (cnt < 0) {
		for(;;) {
			res = read_input_container(input, &nmsg);
			if (res == nmsg_res_success) {
				for (n = 0; n < nmsg->n_payloads; n++)
					cb(nmsg->payloads[n], user);
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			} else {
				return (res);
			}
		}
	} else {
		for (i = 0; i < cnt; i++) {
			res = read_input_container(input, &nmsg);
			if (res == nmsg_res_success) {
				for (n = 0; n < nmsg->n_payloads; n++)
					cb(nmsg->payloads[n], user);
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			} else {
				return (res);
			}
		}
	}
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

	/* nmsg_stream_input */
	input->stream = calloc(1, sizeof(*(input->stream)));
	if (input->stream == NULL) {
		free(input);
		return (NULL);
	}
	input->stream->type = type;

	/* nmsg_buf */
	input->stream->buf = nmsg_buf_new(NMSG_RBUFSZ);
	if (input->stream->buf == NULL) {
		free(input->stream);
		free(input);
		return (NULL);
	}
	nmsg_buf_reset(input->stream->buf);
	input->stream->buf->fd = fd;
	input->stream->buf->bufsz = NMSG_RBUFSZ / 2;

	/* nmsg_zbuf */
	input->stream->zb = nmsg_zbuf_inflate_init();
	if (input->stream->zb == NULL) {
		nmsg_buf_destroy(&input->stream->buf);
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
	bytes_avail = nmsg_buf_avail(buf);
	if (bytes_avail < NMSG_HDRSZ) {
		if (input->stream->type == nmsg_stream_type_file) {
			assert(bytes_avail >= 0);
			bytes_needed = NMSG_HDRSZ - bytes_avail;
			if (bytes_avail == 0) {
				nmsg_buf_reset(buf);
				res = read_input(input, bytes_needed, buf->bufsz);
			} else {
				/* the (magic, version) header was split */
				res = read_input(input, bytes_needed,
						 bytes_needed);
				reset_buf = true;
			}
		} else if (input->stream->type == nmsg_stream_type_sock) {
			assert(bytes_avail == 0);
			nmsg_buf_reset(buf);
			res = read_input_oneshot(input, NMSG_HDRSZ, buf->bufsz);
		}
		if (res != nmsg_res_success)
			return (res);
	}
	bytes_avail = nmsg_buf_avail(buf);
	assert(bytes_avail >= NMSG_HDRSZ);

	/* check magic */
	if (memcmp(buf->pos, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	buf->pos += sizeof(magic);

	/* check version */
	vers = ntohs(*(uint16_t *) buf->pos);
	buf->pos += sizeof(vers);
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
		nmsg_buf_reset(buf);
		reset_buf = false;
	}

	/* ensure we have the length header */
	bytes_avail = nmsg_buf_avail(buf);
	if (bytes_avail < lenhdrsz) {
		if (bytes_avail == 0)
			nmsg_buf_reset(buf);
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
	bytes_avail = nmsg_buf_avail(buf);
	assert(bytes_avail >= lenhdrsz);

	/* load message size */
	if (vers == 1U) {
		*msgsize = ntohs(*(uint16_t *) buf->pos);
		buf->pos += sizeof(uint16_t);
	} else if (vers == 2U) {
		*msgsize = ntohl(*(uint32_t *) buf->pos);
		buf->pos += sizeof(uint32_t);
	}

	res = nmsg_res_success;

read_header_out:
	if (reset_buf == true)
		nmsg_buf_reset(buf);

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
	ssize_t bytes_read;
	struct nmsg_buf *buf;

	buf = input->stream->buf;

	/* sanity check */
	assert(bytes_needed <= bytes_max);

	/* check that we have enough buffer space */
	assert((buf->end + bytes_max) <= (buf->data + NMSG_RBUFSZ));

	if (poll(&input->stream->pfd, 1, NMSG_RBUF_TIMEOUT) == 0)
		return (nmsg_res_again);
	bytes_read = read(buf->fd, buf->pos, bytes_max);
	if (bytes_read < 0)
		return (nmsg_res_failure);
	if (bytes_read == 0)
		return (nmsg_res_eof);
	buf->end = buf->pos + bytes_read;
	assert(bytes_read >= bytes_needed);
	nmsg_timespec_get(&input->stream->now);
	return (nmsg_res_success);
}

static nmsg_res
read_input_container(nmsg_input_t input, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail, msgsize;
	struct nmsg_buf *buf;

	buf = input->stream->buf;

	/* read the header */
	res = read_header(input, &msgsize);
	if (res != nmsg_res_success &&
	    input->stream->type == nmsg_stream_type_sock)
	{
		/* forward compatibility */
		return (nmsg_res_again);
	}
	if (res != nmsg_res_success)
		return (res);

	/* if the input stream is a file stream, read the nmsg container */
	bytes_avail = nmsg_buf_avail(buf);
	if (input->stream->type == nmsg_stream_type_file &&
	    bytes_avail < msgsize)
	{
		ssize_t bytes_to_read = msgsize - bytes_avail;

		res = read_input(input, bytes_to_read, bytes_to_read);
		if (res != nmsg_res_success)
			return (res);
	}
	/* if the input stream is a sock stream, then the entire message must
	 * have been read by the call to read_header() */
	else if (input->stream->type == nmsg_stream_type_sock)
		assert(nmsg_buf_avail(buf) == msgsize);

	/* unpack message */
	if (input->stream->flags & NMSG_FLAG_FRAGMENT) {
		res = read_input_frag(input, msgsize, nmsg);
	} else if (input->stream->flags & NMSG_FLAG_ZLIB) {
		size_t ulen;
		u_char *ubuf;

		res = nmsg_zbuf_inflate(input->stream->zb, msgsize, buf->pos,
					&ulen, &ubuf);
		if (res != nmsg_res_success)
			return (res);
		*nmsg = nmsg__nmsg__unpack(NULL, ulen, ubuf);
		assert(*nmsg != NULL);
		free(ubuf);
	} else {
		*nmsg = nmsg__nmsg__unpack(NULL, msgsize, buf->pos);
		assert(*nmsg != NULL);
	}
	buf->pos += msgsize;

	/* if the input stream is a sock stream, then expire old outstanding
	 * fragments */
	if (input->stream->type == nmsg_stream_type_sock &&
	    input->stream->nfrags > 0 &&
	    input->stream->now.tv_sec - input->stream->lastgc.tv_sec >=
		NMSG_FRAG_GC_INTERVAL)
	{
		gc_frags(input->stream);
		input->stream->lastgc = input->stream->now;
	}

	return (res);
}

#include "input_frag.c"
