/* nmsg_output - interface for writing nmsg messages */

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
#include "private.h"
#include "nmsg/constants.h"
#include "nmsg/output.h"
#include "nmsg/rate.h"

/* Forward. */

static nmsg_buf output_open(nmsg_buf_type, int, size_t);
static nmsg_res write_buf(nmsg_buf);
static nmsg_res write_pbuf(nmsg_buf buf);
static void free_payloads(Nmsg__Nmsg *nc, ProtobufCAllocator *ca);
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
nmsg_output_open_pres(int fd) {
	struct nmsg_pres *pres;

	pres = calloc(1, sizeof(*pres));
	if (pres == NULL)
		return (NULL);
	pres->fd = fd;
	pres->type = nmsg_pres_type_write;
	return (pres);
}

nmsg_res
nmsg_output_append(nmsg_buf buf, Nmsg__NmsgPayload *np) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;
	size_t np_plen;

	res = nmsg_res_success;

	nmsg = (Nmsg__Nmsg *) buf->wbuf.nmsg;
	if (!(buf->type == nmsg_buf_type_write_file ||
	      buf->type == nmsg_buf_type_write_sock))
		return (nmsg_res_wrong_buftype);
	if (nmsg == NULL) {
		nmsg = buf->wbuf.nmsg = calloc(1, sizeof(Nmsg__Nmsg));
		if (nmsg == NULL)
			return (nmsg_res_failure);
		nmsg->base.descriptor = &nmsg__nmsg__descriptor;
	}
	if (np->has_payload)
		np_plen = np->payload.len;
	else
		np_plen = 0;

	/* XXX hacks be here */

	if (np_plen >= buf->bufsz) {
		fprintf(stderr, "ERROR: payload length (%zd) "
			"larger than buffer (%zd)\n",
			np_plen, buf->bufsz);
		return (nmsg_res_failure);
	}
	if (buf->wbuf.estsz != 0 &&
	    buf->wbuf.estsz + np_plen + 192 >= buf->bufsz)
	{
		res = write_pbuf(buf);
		if (res != nmsg_res_success)
			return (res);
		res = nmsg_res_pbuf_written;
		free_payloads(nmsg, buf->wbuf.ca);
		nmsg->n_payloads = 0;
		buf->wbuf.estsz = 0;
		if (res == nmsg_res_pbuf_written && buf->wbuf.rate != NULL)
			nmsg_rate_sleep(buf->wbuf.rate);
	}
	buf->wbuf.estsz += np_plen + 20;

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
	if ((*buf)->wbuf.estsz > 0) {
		res = write_pbuf(*buf);
		if (res == nmsg_res_success) {
			free_payloads(nmsg, (*buf)->wbuf.ca);
			res = nmsg_res_pbuf_written;
		}
	}
	free(nmsg->payloads);
	free(nmsg);
	nmsg_buf_destroy(buf);
	return (res);
}

void
nmsg_output_set_allocator(nmsg_buf buf, ProtobufCAllocator *ca) {
	buf->wbuf.ca = ca;
}

void
nmsg_output_set_rate(nmsg_buf buf, unsigned rate, unsigned freq) {
	if (buf->wbuf.rate != NULL)
		nmsg_rate_destroy(&buf->wbuf.rate);
	buf->wbuf.rate = nmsg_rate_init(rate, freq);
}

/* Private. */

nmsg_buf
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
	return (buf);
}

static void
free_payloads(Nmsg__Nmsg *nc, ProtobufCAllocator *ca) {
	if (ca != NULL) {
		unsigned i;

		for (i = 0; i < nc->n_payloads; i++) {
			if (nc->payloads[i]->has_payload) {
				ca->free(ca->allocator_data,
					 nc->payloads[i]);
			}
		}
	}
	nc->n_payloads = 0;
}

static nmsg_res
write_pbuf(nmsg_buf buf) {
	Nmsg__Nmsg *nc;
	size_t len;
	uint16_t *len_wire;

	nc = (Nmsg__Nmsg *) buf->wbuf.nmsg;
	write_header(buf);
	len_wire = (uint16_t *) buf->pos;
	buf->pos += sizeof(*len_wire);

	len = nmsg__nmsg__pack(nc, buf->pos);
	*len_wire = htons(len);
	buf->pos += len;
	return (write_buf(buf));
}

static nmsg_res
write_buf(nmsg_buf buf) {
	ssize_t len, bytes_written;

	len = nmsg_buf_bytes(buf);
	if (len > (ssize_t) buf->bufsz)
		return (nmsg_res_msgsize_toolarge);
	bytes_written = write(buf->fd, buf->data, (size_t) len);
	if (bytes_written == -1)
		return (nmsg_res_failure);
	if (bytes_written < len)
		return (nmsg_res_short_send);
	return (nmsg_res_success);
}

static void
write_header(nmsg_buf buf) {
	char magic[] = NMSG_MAGIC;
	uint16_t vers;

	buf->pos = buf->data;
	memcpy(buf->pos, magic, sizeof(magic));
	buf->pos += sizeof(magic);
	vers = htons(NMSG_VERSION);
	memcpy(buf->pos, &vers, sizeof(vers));
	buf->pos += sizeof(vers);
}
