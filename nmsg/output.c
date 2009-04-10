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
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "private.h"

/* Macros. */

#define reset_estsz(stream) do { (stream)->estsz = NMSG_HDRLSZ_V2; } while (0)

/* Forward. */

static nmsg_output_t output_open_stream(nmsg_stream_type, int, size_t);
static nmsg_res write_output(nmsg_output_t output);
static nmsg_res write_output_frag(nmsg_output_t output);
static nmsg_res write_pbuf(nmsg_output_t output);
static void free_payloads(Nmsg__Nmsg *nc);
static void write_header(struct nmsg_buf *buf, uint8_t flags);

/* Export. */

nmsg_output_t
nmsg_output_open_file(int fd, size_t bufsz) {
	return (output_open_stream(nmsg_stream_type_file, fd, bufsz));
}

nmsg_output_t
nmsg_output_open_sock(int fd, size_t bufsz) {
	return (output_open_stream(nmsg_stream_type_sock, fd, bufsz));
}

nmsg_output_t
nmsg_output_open_pres(int fd, bool flush) {
	struct nmsg_output *output;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_pres;

	output->pres = calloc(1, sizeof(*(output->pres)));
	if (output->pres == NULL) {
		free(output);
		return (NULL);
	}
	output->pres->fp = fdopen(fd, "w");
	if (output->pres->fp == NULL) {
		free(output->pres);
		free(output);
		return (NULL);
	}
	if (flush == true) {
		if (setvbuf(output->pres->fp, NULL, _IOLBF, 0) != 0) {
			fclose(output->pres->fp);
			free(output->pres);
			free(output);
			return (NULL);
		}
	}
	output->pres->flush = flush;

	return (output);
}

nmsg_res
nmsg_output_append(nmsg_output_t output, Nmsg__NmsgPayload *np) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;
	size_t np_len;

	res = nmsg_res_success;
	nmsg = output->stream->nmsg;

	/* initialize nmsg container if necessary */
	if (nmsg == NULL) {
		nmsg = output->stream->nmsg = calloc(1, sizeof(Nmsg__Nmsg));
		if (nmsg == NULL)
			return (nmsg_res_failure);
		nmsg__nmsg__init(nmsg);
	}

	np_len = nmsg_payload_size(np);

	/* check for overflow */
	if (output->stream->estsz != NMSG_HDRLSZ_V2 &&
	    output->stream->estsz + np_len + 16 >= output->stream->buf->bufsz)
	{
		/* finalize and write out the container */
		res = write_pbuf(output);
		if (res != nmsg_res_success) {
			if (np->has_payload && np->payload.data != NULL)
				free(np->payload.data);
			free(np);
			free_payloads(nmsg);
			reset_estsz(output->stream);
			return (res);
		}
		res = nmsg_res_pbuf_written;
		free_payloads(nmsg);
		reset_estsz(output->stream);

		/* sleep a bit if necessary */
		if (output->stream->rate != NULL)
			nmsg_rate_sleep(output->stream->rate);
	}

	/* field tag */
	output->stream->estsz += 1;

	/* varint encoded length */
	output->stream->estsz += 1;
	if (np_len >= (1 << 7))
		output->stream->estsz += 1;
	if (np_len >= (1 << 14))
		output->stream->estsz += 1;
	if (np_len >= (1 << 21))
		output->stream->estsz += 1;

	/* increment estimated size of serialized container */
	output->stream->estsz += np_len;

	/* append payload to container */
	nmsg->payloads = realloc(nmsg->payloads,
				 ++(nmsg->n_payloads) * sizeof(void *));
	if (nmsg->payloads == NULL)
		return (nmsg_res_memfail);
	nmsg->payloads[nmsg->n_payloads - 1] = np;

	/* check if payload needs to be fragmented */
	if (output->stream->estsz > output->stream->buf->bufsz) {
		res = write_output_frag(output);
		free_payloads(nmsg);
		reset_estsz(output->stream);
		return (res);
	}

	/* flush output if unbuffered */
	if (output->stream->buffered == false) {
		res = write_pbuf(output);
		if (res == nmsg_res_success)
			res = nmsg_res_pbuf_written;
		free_payloads(nmsg);
		reset_estsz(output->stream);

		/* sleep a bit if necessary */
		if (output->stream->rate != NULL)
			nmsg_rate_sleep(output->stream->rate);
	}

	return (res);
}

nmsg_res
nmsg_output_close(nmsg_output_t *output) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;

	res = nmsg_res_success;
	switch ((*output)->type) {
	case nmsg_output_type_stream:
		nmsg = (*output)->stream->nmsg;

		if ((*output)->stream->rate != NULL)
			nmsg_rate_destroy(&((*output)->stream->rate));
		if ((*output)->stream->estsz > NMSG_HDRLSZ_V2) {
			res = write_pbuf(*output);
			if (res == nmsg_res_success)
				res = nmsg_res_pbuf_written;
		}
		if ((*output)->stream->zb != NULL) {
			nmsg_zbuf_destroy(&((*output)->stream->zb));
			free((*output)->stream->zb_tmp);
		}
		if (nmsg != NULL) {
			free_payloads(nmsg);
			free(nmsg->payloads);
			free(nmsg);
		}
		nmsg_buf_destroy(&(*output)->stream->buf);
		free((*output)->stream);
		break;
	case nmsg_output_type_pres:
		fclose((*output)->pres->fp);
		free((*output)->pres);
		break;
	}
	free(*output);
	*output = NULL;
	return (res);
}

void
nmsg_output_set_buffered(nmsg_output_t output, bool buffered) {
	assert(output->stream->type == nmsg_stream_type_sock);
	output->stream->buffered = buffered;
}

void
nmsg_output_set_rate(nmsg_output_t output, nmsg_rate_t rate) {
	if (output->stream->rate != NULL)
		nmsg_rate_destroy(&output->stream->rate);
	output->stream->rate = rate;
}

void
nmsg_output_set_zlibout(nmsg_output_t output, bool zlibout) {
	if (output->type != nmsg_output_type_stream)
		return;

	if (zlibout == true) {
		if (output->stream->zb == NULL) {
			output->stream->zb = nmsg_zbuf_deflate_init();
			assert(output->stream->zb != NULL);
		}
		if (output->stream->zb_tmp == NULL) {
			output->stream->zb_tmp = calloc(1,
				output->stream->buf->bufsz);
			assert(output->stream->zb_tmp != NULL);
		}
	} else if (zlibout == false) {
		if (output->stream->zb != NULL)
			nmsg_zbuf_destroy(&output->stream->zb);
		if (output->stream->zb_tmp != NULL) {
			free(output->stream->zb_tmp);
			output->stream->zb_tmp = NULL;
		}
	}
}

/* Private. */

static nmsg_output_t
output_open_stream(nmsg_stream_type type, int fd, size_t bufsz) {
	struct nmsg_output *output;

	/* nmsg_output */
	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_stream;

	/* nmsg_stream_output */
	output->stream = calloc(1, sizeof(*(output->stream)));
	if (output->stream == NULL) {
		free(output);
		return (NULL);
	}
	output->stream->type = type;
	output->stream->buffered = true;
	reset_estsz(output->stream);

	/* nmsg_buf */
	if (bufsz < NMSG_WBUFSZ_MIN)
		bufsz = NMSG_WBUFSZ_MIN;
	if (bufsz > NMSG_WBUFSZ_MAX)
		bufsz = NMSG_WBUFSZ_MAX;
	output->stream->buf = nmsg_buf_new(bufsz);
	if (output->stream->buf == NULL) {
		free(output->stream);
		free(output);
		return (NULL);
	}
	output->stream->buf->fd = fd;
	output->stream->buf->bufsz = bufsz;

	/* seed the rng, needed for fragment IDs */
	{
		struct timespec ts;
		nmsg_timespec_get(&ts);
		srandom(ts.tv_sec ^ ts.tv_nsec ^ getpid());
	}

	return (output);
}

static void
free_payloads(Nmsg__Nmsg *nc) {
	unsigned i;

	for (i = 0; i < nc->n_payloads; i++) {
		if (nc->payloads[i]->has_payload)
			free(nc->payloads[i]->payload.data);
		if (nc->payloads[i]->n_user > 0)
			free(nc->payloads[i]->user);
		free(nc->payloads[i]);
	}
	nc->n_payloads = 0;
}

static nmsg_res
write_pbuf(nmsg_output_t output) {
	Nmsg__Nmsg *nc;
	size_t len;
	uint32_t *len_wire;
	struct nmsg_buf *buf;

	buf = output->stream->buf;
	nc = output->stream->nmsg;
	write_header(buf, (output->stream->zb != NULL) ? NMSG_FLAG_ZLIB : 0);
	len_wire = (uint32_t *) buf->pos;
	buf->pos += sizeof(*len_wire);

	if (output->stream->zb == NULL) {
		len = nmsg__nmsg__pack(nc, buf->pos);
	} else {
		nmsg_res res;
		size_t ulen;

		ulen = nmsg__nmsg__pack(nc, output->stream->zb_tmp);
		len = buf->bufsz;
		res = nmsg_zbuf_deflate(output->stream->zb, ulen,
					output->stream->zb_tmp, &len,
					buf->pos);
		if (res != nmsg_res_success)
			return (res);
	}
	*len_wire = htonl(len);
	buf->pos += len;
	return (write_output(output));
}

static nmsg_res
write_output_frag(nmsg_output_t output) {
	Nmsg__Nmsg *nc;
	Nmsg__NmsgFragment nf;
	int i;
	nmsg_res res;
	size_t len, zlen, fragpos, fragsz, fraglen, max_fragsz;
	ssize_t bytes_written;
	struct iovec iov[2];
	uint32_t *len_wire;
	uint8_t flags, *packed, *frag_packed;
	struct nmsg_buf *buf;

	buf = output->stream->buf;
	flags = 0;
	nc = output->stream->nmsg;
	nmsg__nmsg_fragment__init(&nf);
	max_fragsz = buf->bufsz - 32;

	/* allocate a buffer large enough to hold the unfragmented nmsg */
	packed = malloc(output->stream->estsz);
	if (packed == NULL)
		return (nmsg_res_memfail);

	len = nmsg__nmsg__pack(nc, packed);

	/* compress the unfragmented nmsg if requested */
	if (output->stream->zb != NULL) {
		uint8_t *zpacked;

		flags = NMSG_FLAG_ZLIB;

		/* allocate a buffer large enough to hold the compressed,
		 * unfragmented nmsg */
		zlen = 2 * output->stream->estsz;
		zpacked = malloc(zlen);
		if (zpacked == NULL) {
			free(packed);
			return (nmsg_res_memfail);
		}

		/* compress the unfragmented nmsg and replace the uncompressed
		 * nmsg with the compressed version */
		res = nmsg_zbuf_deflate(output->stream->zb, len, packed, &zlen,
					zpacked);
		free(packed);
		if (res != nmsg_res_success) {
			free(zpacked);
			return (res);
		}
		packed = zpacked;
		len = zlen;

		/* write out the unfragmented nmsg if it's small enough after
		 * compression */
		if (len <= max_fragsz) {
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
			else if (output->stream->type != nmsg_stream_type_sock)
				assert(bytes_written == (ssize_t)
				       (NMSG_HDRLSZ_V2 + len));
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
	nf.last = len / max_fragsz;
	for (fragpos = 0, i = 0;
	     fragpos < len;
	     fragpos += max_fragsz, i++)
	{
		/* serialize the fragment */
		nf.current = i;
		fragsz = (len - fragpos > max_fragsz)
			? max_fragsz : (len - fragpos);
		nf.fragment.len = fragsz;
		nf.fragment.data = packed + fragpos;
		fraglen = nmsg__nmsg_fragment__pack(&nf, frag_packed);

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
		else if (output->stream->type != nmsg_stream_type_sock)
			assert(bytes_written == (ssize_t)
			       (NMSG_HDRLSZ_V2 + fraglen));
	}
	free(frag_packed);

frag_out:
	free(packed);
	free_payloads(nc);

	return (nmsg_res_success);
}

static nmsg_res
write_output(nmsg_output_t output) {
	ssize_t bytes_written;
	size_t len;
	struct nmsg_buf *buf;

	buf = output->stream->buf;

	len = nmsg_buf_used(buf);
	assert(len <= buf->bufsz);

	if (output->stream->type == nmsg_stream_type_sock) {
		bytes_written = write(buf->fd, buf->data, len);
		if (bytes_written < 0) {
			perror("write");
			return (nmsg_res_failure);
		}
		assert((size_t) bytes_written == len);
	} else if (output->stream->type == nmsg_stream_type_file) {
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
write_header(struct nmsg_buf *buf, uint8_t flags) {
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
