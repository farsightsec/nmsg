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
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "private.h"
#include "constants.h"
#include "output.h"
#include "payload.h"
#include "rate.h"
#include "res.h"

/* Forward. */

static nmsg_buf output_open(nmsg_buf_type, int, size_t);
static nmsg_res write_buf(nmsg_buf);
static nmsg_res write_pbuf(nmsg_buf buf);
static void free_payloads(Nmsg__Nmsg *nc);
static void write_header(nmsg_buf buf);

/* Export. */

nmsg_buf
nmsg_output_open_file(int fd, size_t bufsz) {
	return (output_open(nmsg_buf_type_write_file, fd, bufsz));
}

nmsg_buf
nmsg_output_open_sock(int fd, size_t bufsz) {
	return (output_open(nmsg_buf_type_write_sock, fd, bufsz));
}

nmsg_pres
nmsg_output_open_pres(int fd, int flush) {
	struct nmsg_pres *pres;

	pres = calloc(1, sizeof(*pres));
	if (pres == NULL)
		return (NULL);
	pres->fd = fd;
	pres->type = nmsg_pres_type_write;
	if (flush > 0)
		pres->flush = true;
	return (pres);
}

nmsg_res
nmsg_output_append(nmsg_buf buf, Nmsg__NmsgPayload *np) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;
	size_t np_len;

	res = nmsg_res_success;

	nmsg = buf->wbuf.nmsg;
	if (!(buf->type == nmsg_buf_type_write_file ||
	      buf->type == nmsg_buf_type_write_sock))
		return (nmsg_res_wrong_buftype);
	if (nmsg == NULL) {
		nmsg = buf->wbuf.nmsg = calloc(1, sizeof(Nmsg__Nmsg));
		if (nmsg == NULL)
			return (nmsg_res_failure);
		nmsg->base.descriptor = &nmsg__nmsg__descriptor;
	}
	np_len = nmsg_payload_size(np);
	assert(np_len <= buf->bufsz);

	if (buf->wbuf.estsz != NMSG_HDRLSZ_V2 &&
	    buf->wbuf.estsz + np_len + 16 >= buf->bufsz)
	{
		res = write_pbuf(buf);
		if (res != nmsg_res_success) {
			if (np->has_payload && np->payload.data != NULL)
				free(np->payload.data);
			free(np);
			free_payloads(nmsg);
			buf->wbuf.estsz = NMSG_HDRLSZ_V2;
			return (res);
		}
		res = nmsg_res_pbuf_written;
		free_payloads(nmsg);
		buf->wbuf.estsz = NMSG_HDRLSZ_V2;
		if (res == nmsg_res_pbuf_written && buf->wbuf.rate != NULL)
			nmsg_rate_sleep(buf->wbuf.rate);
	}

	/* field tag */
	buf->wbuf.estsz += 1;

	/* varint encoded length */
	buf->wbuf.estsz += 1;
	if (np_len >= (1 << 7))
		buf->wbuf.estsz += 1;
	if (np_len >= (1 << 14))
		buf->wbuf.estsz += 1;
	if (np_len >= (1 << 21))
		buf->wbuf.estsz += 1;

	buf->wbuf.estsz += np_len;
	assert(buf->wbuf.estsz <= buf->bufsz);

	nmsg->payloads = realloc(nmsg->payloads,
				 ++(nmsg->n_payloads) * sizeof(void *));
	nmsg->payloads[nmsg->n_payloads - 1] = np;
	return (res);
}

nmsg_res
nmsg_output_close(nmsg_buf *buf) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;

	res = nmsg_res_success;
	nmsg = (Nmsg__Nmsg *) (*buf)->wbuf.nmsg;
	if (!((*buf)->type == nmsg_buf_type_write_file ||
	      (*buf)->type == nmsg_buf_type_write_sock))
		return (nmsg_res_wrong_buftype);
	if ((*buf)->wbuf.rate != NULL)
		nmsg_rate_destroy(&((*buf)->wbuf.rate));
	if (nmsg == NULL) {
		nmsg_buf_destroy(buf);
		return (nmsg_res_success);
	}
	if ((*buf)->wbuf.estsz > NMSG_HDRLSZ_V2) {
		res = write_pbuf(*buf);
		if (res == nmsg_res_success)
			res = nmsg_res_pbuf_written;
	}
	free_payloads(nmsg);
	free(nmsg->payloads);
	free(nmsg);
	nmsg_buf_destroy(buf);
	return (res);
}

void
nmsg_output_close_pres(nmsg_pres *pres) {
	free(*pres);
	*pres = NULL;
}

void
nmsg_output_set_rate(nmsg_buf buf, nmsg_rate rate) {
	if (buf->wbuf.rate != NULL)
		nmsg_rate_destroy(&buf->wbuf.rate);
	buf->wbuf.rate = rate;
}

/* Private. */

static nmsg_buf
output_open(nmsg_buf_type type, int fd, size_t bufsz) {
	nmsg_buf buf;

	if (bufsz < NMSG_WBUFSZ_MIN)
		bufsz = NMSG_WBUFSZ_MIN;
	if (bufsz > NMSG_WBUFSZ_MAX)
		bufsz = NMSG_WBUFSZ_MAX;
	buf = nmsg_buf_new(type, bufsz);
	if (buf == NULL)
		return (NULL);
	buf->fd = fd;
	buf->bufsz = bufsz;
	buf->wbuf.estsz = NMSG_HDRLSZ_V2;
	return (buf);
}

static void
free_payloads(Nmsg__Nmsg *nc) {
	unsigned i;

	for (i = 0; i < nc->n_payloads; i++) {
		if (nc->payloads[i]->has_payload)
			free(nc->payloads[i]->payload.data);
		free(nc->payloads[i]);
	}
	nc->n_payloads = 0;
}

static nmsg_res
write_pbuf(nmsg_buf buf) {
	Nmsg__Nmsg *nc;
	size_t len;
	uint32_t *len_wire;

	nc = (Nmsg__Nmsg *) buf->wbuf.nmsg;
	write_header(buf);
	len_wire = (uint32_t *) buf->pos;
	buf->pos += sizeof(*len_wire);

	len = nmsg__nmsg__pack(nc, buf->pos);
	*len_wire = htonl(len);
	buf->pos += len;
	return (write_buf(buf));
}

static nmsg_res
write_buf(nmsg_buf buf) {
	ssize_t len, bytes_written;

	len = nmsg_buf_used(buf);
	if (len > (ssize_t) buf->bufsz)
		return (nmsg_res_msgsize_toolarge);
	bytes_written = write(buf->fd, buf->data, (size_t) len);
	if (bytes_written == -1) {
		perror("write");
		return (nmsg_res_failure);
	}
	if (bytes_written < len)
		return (nmsg_res_failure);
	return (nmsg_res_success);
}

static void
write_header(nmsg_buf buf) {
	char magic[] = NMSG_MAGIC;
	uint16_t vers;

	buf->pos = buf->data;
	memcpy(buf->pos, magic, sizeof(magic));
	buf->pos += sizeof(magic);
	vers = NMSG_VERSION;
	vers = htons(vers);
	memcpy(buf->pos, &vers, sizeof(vers));
	buf->pos += sizeof(vers);
}
