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

#include <stdlib.h>
#include <unistd.h>

#include "nmsg.h"
#include "private.h"

/* Export. */

nmsg_buf
nmsg_buf_new(nmsg_buf_type type, size_t sz) {
	nmsg_buf buf;

	buf = calloc(1, sizeof(*buf));
	if (buf == NULL)
		return (NULL);
	buf->data = malloc(sz);
	if (buf->data == NULL) {
		free(buf);
		return (NULL);
	}
	buf->type = type;
	return (buf);
}

nmsg_res
nmsg_buf_ensure(nmsg_buf buf, ssize_t bytes) {
	nmsg_res res;

	if (bytes < 0)
		return (nmsg_res_failure);
	if (nmsg_buf_avail(buf) < bytes) {
		res = nmsg_buf_fill(buf);
		if (res == nmsg_res_success && nmsg_buf_avail(buf) < bytes)
			return (nmsg_res_failure);
		else
			return (res);
	}
	return (nmsg_res_success);
}

nmsg_res
nmsg_buf_fill(nmsg_buf buf) {
	ssize_t bytes_needed = 0, bytes_read = 0;

	bytes_needed = buf->bufsz;
	
	while (bytes_needed > 0) {
		while (poll(&buf->rbuf.pfd, 1, 500) == 0);
		bytes_read += read(buf->fd, buf->data + bytes_read, bytes_needed);
		bytes_needed -= bytes_read;
		if (bytes_read < 0)
			return (nmsg_res_failure);
		if (bytes_read == 0)
			return (nmsg_res_eof);
	}
	buf->pos = buf->data;
	buf->end = buf->data + bytes_read;
	return (nmsg_res_success);
}

ssize_t
nmsg_buf_bytes(nmsg_buf buf) {
	if (buf->pos < buf->data)
		return (-1);
	return (buf->pos - buf->data);
}

ssize_t
nmsg_buf_avail(nmsg_buf buf) {
	if (buf->pos > buf->end)
		return (-1);
	return (buf->end - buf->pos);
}

void
nmsg_buf_destroy(nmsg_buf *buf) {
	close((*buf)->fd);
	free((*buf)->data);
	free(*buf);
	*buf = NULL;
}
