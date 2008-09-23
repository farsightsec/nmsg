/* nmsg_write.c - interface for writing nmsg messages */

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
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "nmsg_private.h"

/* Forward. */

static nmsg_res write_buf(nmsg_buf);
static nmsg_res write_pbuf(nmsg_buf buf);
static void write_header(nmsg_buf buf);
static void write_len(nmsg_buf buf, uint16_t len);

/* Export. */

nmsg_buf
nmsg_output_open_fd(int fd, size_t bufsz) {
	nmsg_buf buf;
	
	if (bufsz < nmsg_wbufsize_min)
		bufsz = nmsg_wbufsize_min;
	if (bufsz > nmsg_wbufsize_max)
		bufsz = nmsg_wbufsize_max;
	buf = nmsg_buf_new(nmsg_buf_type_write, bufsz);
	if (buf == NULL)
		return (NULL);
	buf->fd = fd;
	buf->bufsz = bufsz;
	return (buf);
}

nmsg_res
nmsg_output_append(nmsg_buf buf, Nmsg__NmsgPayload *np) {
	Nmsg__Nmsg *nc;
	nmsg_res res;
	size_t nc_plen, np_plen;

	nc = (Nmsg__Nmsg *) buf->user;
	if (buf->type != nmsg_buf_type_write)
		return (nmsg_res_wrong_buftype);
	if (nc == NULL) {
		nc = buf->user = calloc(1, sizeof(Nmsg__Nmsg));
		if (nc == NULL)
			return (nmsg_res_failure);
		nc->base.descriptor = &nmsg__nmsg__descriptor;
	}
	nc_plen = nmsg__nmsg__get_packed_size(nc);
	np_plen = nmsg__nmsg_payload__get_packed_size(np);
	if (nc_plen + np_plen + 192 >= buf->bufsz) {
		unsigned i;

		res = write_pbuf(buf);
		if (res != nmsg_res_success)
			return (res);
		for (i = 0; i < nc->n_payloads; i++) {
			if (nc->payloads[i]->has_payload)
				free(nc->payloads[i]->payload.data);
		}
		nc->n_payloads = 0;
	}

	nc->payloads = realloc(nc->payloads, ++(nc->n_payloads) * sizeof(void *));
	nc->payloads[nc->n_payloads - 1] = np;
	return (nmsg_res_success);
}

nmsg_res
nmsg_output_close(nmsg_buf *buf) {
	Nmsg__Nmsg *nc;
	nmsg_res res;

	nc = (Nmsg__Nmsg *) (*buf)->user;
	if ((*buf)->type != nmsg_buf_type_write)
		return (nmsg_res_wrong_buftype);
	if (nc == NULL) {
		nmsg_buf_destroy(buf);
		return (nmsg_res_success);
	}
	res = write_pbuf(*buf);
	if (res == nmsg_res_success) {
		unsigned i;
		
		for (i = 0; i < nc->n_payloads; i++) {
			if (nc->payloads[i]->has_payload)
				free(nc->payloads[i]->payload.data);
		}
	}
	free(nc->payloads);
	free(nc);
	nmsg_buf_destroy(buf);
	return (res);
}

/* Private. */

nmsg_res
write_pbuf(nmsg_buf buf) {
	Nmsg__Nmsg *nc;
	size_t len;

	nc = (Nmsg__Nmsg *) buf->user;
	len = nmsg__nmsg__get_packed_size(nc);
	write_header(buf);
	write_len(buf, len);
	nmsg__nmsg__pack(nc, buf->buf_pos);
	buf->buf_pos += len;
	return (write_buf(buf));
}

nmsg_res
write_buf(nmsg_buf buf) {
	ssize_t len, bytes_written;

	len = nmsg_buf_bytes(buf);
	if (len > (ssize_t) buf->bufsz)
		return (nmsg_res_msgsize_toolarge);
	bytes_written = write(buf->fd, buf->data, (size_t) len);
	printf("wrote %zd bytes\n", bytes_written);
	if (bytes_written == -1)
		return (nmsg_res_failure);
	if (bytes_written < len)
		return (nmsg_res_short_send);
	return (nmsg_res_success);
}

void
write_len(nmsg_buf buf, uint16_t len) {
	uint16_t len_wire;

	len_wire = htons((uint16_t) len);
	memcpy(buf->buf_pos, &len_wire, sizeof(len_wire));
	buf->buf_pos += sizeof(len_wire);
}

void
write_header(nmsg_buf buf) {
	char magic[] = nmsg_magic;
	uint16_t vers;

	buf->buf_pos = buf->data;
	memcpy(buf->buf_pos, magic, sizeof(magic));
	buf->buf_pos += sizeof(magic);
	vers = htons(nmsg_version);
	memcpy(buf->buf_pos, &vers, sizeof(vers));
	buf->buf_pos += sizeof(vers);
}
