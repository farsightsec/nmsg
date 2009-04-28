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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
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
static void input_close_stream(nmsg_input_t input);

static nmsg_res read_header(nmsg_input_t, ssize_t *);
static nmsg_res read_input(nmsg_input_t, ssize_t, ssize_t);
static nmsg_res read_input_oneshot(nmsg_input_t, ssize_t, ssize_t);

/* input_read.c */
static nmsg_res input_read_pcap(nmsg_input_t, Nmsg__NmsgPayload **);
static nmsg_res input_read_pres(nmsg_input_t, Nmsg__NmsgPayload **);
static nmsg_res input_read_nmsg(nmsg_input_t, Nmsg__NmsgPayload **);
static nmsg_res input_read_nmsg_container(nmsg_input_t, Nmsg__Nmsg **);

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

	input->pbmod = pbmod;
	res = nmsg_pbmod_init(input->pbmod, &input->clos);
	if (res != nmsg_res_success) {
		fclose(input->pres->fp);
		free(input->pres);
		free(input);
		return (NULL);
	}

	return (input);
}

nmsg_input_t
nmsg_input_open_pcap(nmsg_pcap_t pcap, nmsg_pbmod_t pbmod) {
	nmsg_res res;
	struct nmsg_input *input;

	input = calloc(1, sizeof(*input));
	if (input == NULL)
		return (NULL);
	input->type = nmsg_input_type_pcap;
	input->read_fp = input_read_pcap;
	input->pcap = pcap;

	input->pbmod = pbmod;
	res = nmsg_pbmod_init(input->pbmod, &input->clos);
	if (res != nmsg_res_success) {
		free(input);
		return (NULL);
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

	if ((*input)->pbmod != NULL)
		nmsg_pbmod_fini((*input)->pbmod, &(*input)->clos);

	free(*input);
	*input = NULL;

	return (nmsg_res_success);
}

nmsg_res
nmsg_input_read(nmsg_input_t input, Nmsg__NmsgPayload **np) {
	return (input->read_fp(input, np));
}

nmsg_res
nmsg_input_flush(nmsg_input_t input) {
	if (input->type == nmsg_input_type_stream) {
		Nmsg__Nmsg *nmsg;
		unsigned i;

		nmsg = input->stream->nmsg;
		assert(nmsg != NULL);

		for (i = 0; i < nmsg->n_payloads; i++)
			if (nmsg->payloads[i] != NULL)
				nmsg_payload_free(&nmsg->payloads[i]);
		nmsg->n_payloads = 0;
		nmsg__nmsg__free_unpacked(nmsg, NULL);
	}

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
			res = input_read_nmsg_container(input, &nmsg);
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
			res = input_read_nmsg_container(input, &nmsg);
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
	input->read_fp = input_read_nmsg;

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

static void
input_close_stream(nmsg_input_t input) {
	if (input->stream->nmsg != NULL)
		nmsg_input_flush(input);

	nmsg_zbuf_destroy(&input->stream->zb);
	free_frags(input->stream);
	nmsg_buf_destroy(&input->stream->buf);
	free(input->stream);
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

#include "input_read.c"
#include "input_frag.c"
