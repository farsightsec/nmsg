/* nmsg_read.c - interface for reading nmsg messages */

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

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "nmsg_private.h"

/* Forward. */

static nmsg_res read_header(nmsg_buf buf);

/* Export. */

nmsg_buf
nmsg_input_open_fd(int fd) {
	nmsg_buf buf;
	
	buf = nmsg_buf_new(nmsg_buf_type_read, nmsg_rbufsize);
	if (buf == NULL)
		return (NULL);
	buf->fd = fd;
	buf->bufsz = nmsg_rbufsize / 2;
	buf->buf_pos = buf->data;
	return (buf);
}

nmsg_res
nmsg_read_pbuf(nmsg_buf buf, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail;
	ssize_t msgsize;

	res = read_header(buf);
	if (res != nmsg_res_success)
		return (res);
	res = nmsg_buf_ensure(buf, sizeof msgsize);
	if (res != nmsg_res_success)
		return (res);
	msgsize = ntohs(*(uint16_t *) buf->buf_pos);
	buf->buf_pos += 2;
	bytes_avail = nmsg_buf_avail(buf);
	while (msgsize > bytes_avail) {
		ssize_t bytes_needed, bytes_read;

		bytes_needed = msgsize - bytes_avail;
		bytes_read = read(buf->fd, buf->buf_end, bytes_needed);
		buf->buf_end += bytes_read;
		bytes_avail = nmsg_buf_avail(buf);
	}
	*nmsg = nmsg__nmsg__unpack(NULL, msgsize, buf->buf_pos);
	buf->buf_pos += msgsize;

	return (nmsg_res_success);
}

nmsg_res
nmsg_loop(nmsg_buf buf, int cnt, nmsg_cb_payload cb, void *user) {
	int i;
	unsigned n;
	nmsg_res res;
	Nmsg__Nmsg *nmsg;

	if (cnt < 0) {
		for(;;) {
			res = nmsg_read_pbuf(buf, &nmsg);
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
			res = nmsg_read_pbuf(buf, &nmsg);
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

nmsg_res
read_header(nmsg_buf buf) {
	char magic[] = nmsg_magic;
	nmsg_res res;
	uint16_t vers;

	res = nmsg_buf_ensure(buf, nmsg_hdrsize);
	if (res != nmsg_res_success)
		return (res);
	if (memcmp(buf->buf_pos, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	buf->buf_pos += sizeof(magic);
	vers = ntohs(*(uint16_t *) buf->buf_pos);
	buf->buf_pos += sizeof(vers);
	if (vers != nmsg_version)
		return (nmsg_res_version_mismatch);
	return (nmsg_res_success);
}
