/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#include "private.h"
#include "constants.h"
#include "input.h"
#include "res.h"

/* Forward. */

static nmsg_buf input_open(nmsg_buf_type, int);
static nmsg_res read_buf(nmsg_buf, ssize_t, ssize_t);
static nmsg_res read_buf_oneshot(nmsg_buf, ssize_t, ssize_t);
static nmsg_res read_header(nmsg_buf, ssize_t *);

/* Export. */

nmsg_buf
nmsg_input_open_file(int fd) {
	return (input_open(nmsg_buf_type_read_file, fd));
}

nmsg_buf
nmsg_input_open_sock(int fd) {
	return (input_open(nmsg_buf_type_read_sock, fd));
}

nmsg_pres
nmsg_input_open_pres(int fd, unsigned vid, unsigned msgtype) {
	struct nmsg_pres *pres;

	pres = calloc(1, sizeof(*pres));
	if (pres == NULL)
		return (NULL);
	pres->fd = fd;
	pres->type = nmsg_pres_type_read;
	pres->vid = vid;
	pres->msgtype = msgtype;
	return (pres);
}

nmsg_res
nmsg_input_close(nmsg_buf *buf) {
	if (!((*buf)->type == nmsg_buf_type_read_file ||
	      (*buf)->type == nmsg_buf_type_read_sock))
		return (nmsg_res_wrong_buftype);
	nmsg_buf_destroy(buf);
	return (nmsg_res_success);
}

nmsg_res
nmsg_input_next(nmsg_buf buf, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail, msgsize;

	res = read_header(buf, &msgsize);
	if (res != nmsg_res_success)
		return (res);
	bytes_avail = nmsg_buf_avail(buf);
	if (buf->type == nmsg_buf_type_read_file && bytes_avail < msgsize) {
		ssize_t bytes_to_read = msgsize - bytes_avail;
		read_buf(buf, bytes_to_read, bytes_to_read);
	}
	else if (buf->type == nmsg_buf_type_read_sock)
		assert(nmsg_buf_avail(buf) == msgsize);
	*nmsg = nmsg__nmsg__unpack(NULL, msgsize, buf->pos);
	buf->pos += msgsize;

	return (nmsg_res_success);
}

nmsg_res
nmsg_input_loop(nmsg_buf buf, int cnt, nmsg_cb_payload cb, void *user) {
	int i;
	unsigned n;
	nmsg_res res;
	Nmsg__Nmsg *nmsg;

	if (cnt < 0) {
		for(;;) {
			res = nmsg_input_next(buf, &nmsg);
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
			res = nmsg_input_next(buf, &nmsg);
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

static nmsg_buf
input_open(nmsg_buf_type type, int fd) {
	struct nmsg_buf *buf;

	buf = nmsg_buf_new(type, NMSG_RBUFSZ);
	if (buf == NULL)
		return (NULL);
	buf->fd = fd;
	buf->bufsz = NMSG_RBUFSZ / 2;
	buf->end = buf->pos = buf->data;
	buf->rbuf.pfd.fd = fd;
	buf->rbuf.pfd.events = POLLIN;
	return (buf);
}

static nmsg_res
read_header(nmsg_buf buf, ssize_t *msgsize) {
	bool reset_buf = false;
	static char magic[] = NMSG_MAGIC;
	ssize_t bytes_avail, bytes_needed;
	nmsg_res res = nmsg_res_failure;
	uint16_t vers;

	/* ensure we have the (magic, version, length) header */
	bytes_avail = nmsg_buf_avail(buf);
	if (bytes_avail < NMSG_HDRLSZ) {
		if (buf->type == nmsg_buf_type_read_file) {
			assert(bytes_avail >= 0);
			bytes_needed = NMSG_HDRLSZ - bytes_avail;
			if (bytes_avail == 0) {
				buf->end = buf->pos = buf->data;
				res = read_buf(buf, bytes_needed, buf->bufsz);
			} else {
				res = read_buf(buf, bytes_needed, bytes_needed);
				reset_buf = true;
			}
		} else if (buf->type == nmsg_buf_type_read_sock) {
			assert(bytes_avail == 0);
			buf->end = buf->pos = buf->data;
			res = read_buf_oneshot(buf, NMSG_HDRLSZ - bytes_avail, buf->bufsz);
		}
		if (res != nmsg_res_success)
			return (res);
	}
	bytes_avail = nmsg_buf_avail(buf);
	assert(bytes_avail >= NMSG_HDRLSZ);

	/* check magic */
	if (memcmp(buf->pos, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	buf->pos += sizeof(magic);

	/* check version */
	vers = ntohs(*(uint16_t *) buf->pos);
	buf->pos += sizeof(vers);
	if (vers != NMSG_VERSION)
		return (nmsg_res_version_mismatch);

	/* load message size */
	*msgsize = ntohs(*(uint16_t *) buf->pos);
	buf->pos += sizeof(uint16_t);

	/* reset the buffer if the header was split */
	if (reset_buf)
		buf->end = buf->pos = buf->data;

	return (nmsg_res_success);
}

static nmsg_res
read_buf(nmsg_buf buf, ssize_t bytes_needed, ssize_t bytes_max) {
	ssize_t bytes_read;
	assert(bytes_needed <= bytes_max);
	assert((buf->end + bytes_max) <= (buf->data + NMSG_RBUFSZ));
	while (bytes_needed > 0) {
		while (poll(&buf->rbuf.pfd, 1, 500) == 0);
		bytes_read = read(buf->fd, buf->end, bytes_max);
		if (bytes_read < 0)
			return (nmsg_res_failure);
		if (bytes_read == 0)
			return (nmsg_res_eof);
		buf->end += bytes_read;
		bytes_needed -= bytes_read;
		bytes_max -= bytes_read;
	}
	return (nmsg_res_success);
}

static nmsg_res
read_buf_oneshot(nmsg_buf buf, ssize_t bytes_needed, ssize_t bytes_max) {
	ssize_t bytes_read;
	assert(bytes_needed <= bytes_max);
	assert((buf->end + bytes_max) <= (buf->data + NMSG_RBUFSZ));
	while (poll(&buf->rbuf.pfd, 1, 500) == 0);
	bytes_read = read(buf->fd, buf->pos, bytes_max);
	if (bytes_read < 0)
		return (nmsg_res_failure);
	if (bytes_read == 0)
		return (nmsg_res_eof);
	buf->end = buf->pos + bytes_read;
	assert(bytes_read >= bytes_needed);
	return (nmsg_res_success);
}
