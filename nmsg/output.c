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

#include "constants.h"
#include "output.h"
#include "payload.h"
#include "private.h"
#include "rate.h"
#include "res.h"
#include "time.h"
#include "zbuf.h"

/* Forward. */

static nmsg_buf output_open(nmsg_buf_type, int, size_t);
static nmsg_res write_buf(nmsg_buf);
static nmsg_res write_frag_pbuf(nmsg_buf);
static nmsg_res write_pbuf(nmsg_buf buf);
static void free_payloads(Nmsg__Nmsg *nc);
static void write_header(nmsg_buf buf, uint8_t flags);

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

	assert(buf->type == nmsg_buf_type_write_file ||
	       buf->type == nmsg_buf_type_write_sock);

	/* initialize nmsg container if necessary */
	if (nmsg == NULL) {
		nmsg = buf->wbuf.nmsg = calloc(1, sizeof(Nmsg__Nmsg));
		if (nmsg == NULL)
			return (nmsg_res_failure);
		nmsg__nmsg__init(nmsg);
	}

	np_len = nmsg_payload_size(np);
	//assert(np_len <= buf->bufsz);

	/* check for overflow */
	if (buf->wbuf.estsz != NMSG_HDRLSZ_V2 &&
	    buf->wbuf.estsz + np_len + 16 >= buf->bufsz)
	{
		/* finalize and write out the container */
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

		/* sleep a bit if necessary */
		if (buf->wbuf.rate != NULL)
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

	/* increment estimated size of serialized container */
	buf->wbuf.estsz += np_len;
	//assert(buf->wbuf.estsz <= buf->bufsz);

	/* append payload to container */
	nmsg->payloads = realloc(nmsg->payloads,
				 ++(nmsg->n_payloads) * sizeof(void *));
	if (nmsg->payloads == NULL)
		return (nmsg_res_memfail);
	nmsg->payloads[nmsg->n_payloads - 1] = np;

	/* check if payload needs to be fragmented */
	if (buf->wbuf.estsz > buf->bufsz) {
		res = write_frag_pbuf(buf);
		free_payloads(nmsg);
		buf->wbuf.estsz = NMSG_HDRLSZ_V2;
	}

	return (res);
}

nmsg_res
nmsg_output_close(nmsg_buf *buf) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;

	res = nmsg_res_success;
	nmsg = (Nmsg__Nmsg *) (*buf)->wbuf.nmsg;
	assert((*buf)->type == nmsg_buf_type_write_file ||
	       (*buf)->type == nmsg_buf_type_write_sock);
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
	if ((*buf)->zb != NULL) {
		nmsg_zbuf_destroy(&(*buf)->zb);
		free((*buf)->zb_tmp);
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

void
nmsg_output_set_zlibout(nmsg_buf buf, bool zlibout) {
	if (zlibout == true) {
		buf->zb = nmsg_zbuf_deflate_init();
		assert(buf->zb != NULL);

		buf->zb_tmp = malloc(buf->bufsz);
		assert(buf->zb_tmp != NULL);
	} else if (zlibout == false) {
		if (buf->zb != NULL) {
			nmsg_zbuf_destroy(&buf->zb);
			free(buf->zb_tmp);
		}
	}
}

/* Private. */

static nmsg_buf
output_open(nmsg_buf_type type, int fd, size_t bufsz) {
	nmsg_buf buf;
	struct timespec ts;

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

	/* seed the rng, needed for fragment IDs */
	nmsg_time_get(&ts);
	srandom(ts.tv_sec ^ ts.tv_nsec ^ getpid());

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
	write_header(buf, (buf->zb != NULL) ? NMSG_FLAG_ZLIB : 0);
	len_wire = (uint32_t *) buf->pos;
	buf->pos += sizeof(*len_wire);

	if (buf->zb == NULL) {
		len = nmsg__nmsg__pack(nc, buf->pos);
	} else {
		nmsg_res res;
		size_t ulen;

		ulen = nmsg__nmsg__pack(nc, buf->zb_tmp);
		len = buf->bufsz;
		res = nmsg_zbuf_deflate(buf->zb, ulen, buf->zb_tmp,
					&len, buf->pos);
		if (res != nmsg_res_success)
			return (res);
	}
	*len_wire = htonl(len);
	buf->pos += len;
	return (write_buf(buf));
}

static nmsg_res
write_frag_pbuf(nmsg_buf buf) {
	Nmsg__Nmsg *nc;
	Nmsg__NmsgFragment nf;
	int i;
	nmsg_res res;
	size_t len, zlen, fragpos, fragsz, fraglen;
	ssize_t bytes_written;
	struct iovec iov[2];
	uint32_t *len_wire;
	uint8_t flags, *packed, *frag_packed;

	flags = 0;
	nc = buf->wbuf.nmsg;
	nmsg__nmsg_fragment__init(&nf);

	/* allocate a buffer large enough to hold the unfragmented nmsg */
	packed = malloc(buf->wbuf.estsz);
	if (packed == NULL)
		return (nmsg_res_memfail);

	len = nmsg__nmsg__pack(nc, packed);

	/* compress the unfragmented nmsg if requested */
	if (buf->zb != NULL) {
		uint8_t *zpacked;

		flags = NMSG_FLAG_ZLIB;

		/* allocate a buffer large enough to hold the compressed,
		 * unfragmented nmsg */
		zlen = 2 * buf->wbuf.estsz;
		zpacked = malloc(zlen);
		if (zpacked == NULL) {
			free(packed);
			return (nmsg_res_memfail);
		}

		/* compress the unfragmented nmsg and replace the uncompressed
		 * nmsg with the compressed version */
		res = nmsg_zbuf_deflate(buf->zb, len, packed, &zlen, zpacked);
		free(packed);
		if (res != nmsg_res_success) {
			free(zpacked);
			return (res);
		}
		packed = zpacked;
		len = zlen;

		/* write out the unfragmented nmsg if it's small enough after
		 * compression */
		if (len < buf->bufsz) {
			write_header(buf, flags);
			len_wire = (uint32_t *) buf->pos;
			*len_wire = htonl(len);

			iov[0].iov_base = buf->data;
			iov[0].iov_len = NMSG_HDRLSZ_V2;
			iov[1].iov_base = packed;
			iov[1].iov_len = len;

			bytes_written = writev(buf->fd, iov, 2);
			if (bytes_written < 0)
				perror("writev");
			assert(bytes_written == (ssize_t)(NMSG_HDRLSZ_V2+len));
			goto frag_out;
		}
	}

	/* allocate a buffer large enough to hold one serialized fragment */
	frag_packed = malloc(buf->bufsz + 32);
	if (frag_packed == NULL)
		goto frag_out;

	/* create and send fragments */
	flags |= NMSG_FLAG_FRAGMENT;
	nf.id = (uint32_t) random();
	nf.last = len / buf->bufsz;
	for (fragpos = 0, i = 0; fragpos < len; fragpos += buf->bufsz, i++) {
		/* serialize the fragment */
		nf.current = i;
		fragsz = (len - fragpos > buf->bufsz)
			? buf->bufsz : (len - fragpos);
		nf.fragment.len = fragsz;
		nf.fragment.data = packed + fragpos;
		fraglen = nmsg__nmsg_fragment__pack(&nf, frag_packed);

		fprintf(stderr, "len=%zd fragpos=%zd fragsz=%zd id=%#.x cur=%u last=%u fraglen=%zu\n", len, fragpos, fragsz, nf.id, nf.current, nf.last, fraglen);

		/* send the serialized fragment */
		write_header(buf, flags);
		len_wire = (uint32_t *) buf->pos;
		*len_wire = htonl(fraglen);

		iov[0].iov_base = buf->data;
		iov[0].iov_len = NMSG_HDRLSZ_V2;
		iov[1].iov_base = frag_packed;
		iov[1].iov_len = fraglen;

		bytes_written = writev(buf->fd, iov, 2);
		if (bytes_written < 0)
			perror("writev");
		assert(bytes_written == (ssize_t) (NMSG_HDRLSZ_V2 + fraglen));
	}
	free(frag_packed);

frag_out:
	free(packed);
	free_payloads(nc);

	return (nmsg_res_success);
}

static nmsg_res
write_buf(nmsg_buf buf) {
	ssize_t bytes_written;
	size_t len;

	len = nmsg_buf_used(buf);
	assert(len <= buf->bufsz);

	if (buf->type == nmsg_buf_type_write_sock) {
		bytes_written = write(buf->fd, buf->data, len);
		if (bytes_written < 0) {
			perror("write");
			return (nmsg_res_failure);
		}
		assert((size_t) bytes_written == len);
	} else if (buf->type == nmsg_buf_type_write_file) {
		const u_char *ptr = buf->data;

		while (len) {
			bytes_written = write(buf->fd, ptr, len);
			if (bytes_written < 0 && errno == EINTR)
				continue;
			if (bytes_written < 0) {
				perror("write");
				return (nmsg_res_failure);
			}
			ptr += bytes_written;
			len -= bytes_written;
		}
	}
	return (nmsg_res_success);
}

static void
write_header(nmsg_buf buf, uint8_t flags) {
	char magic[] = NMSG_MAGIC;
	uint16_t vers;

	buf->pos = buf->data;
	memcpy(buf->pos, magic, sizeof(magic));
	buf->pos += sizeof(magic);
	vers = NMSG_VERSION | (flags << 8);
	vers = htons(vers);
	memcpy(buf->pos, &vers, sizeof(vers));
	buf->pos += sizeof(vers);
}
