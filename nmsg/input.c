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

#include "constants.h"
#include "input.h"
#include "private.h"
#include "res.h"
#include "time.h"
#include "tree.h"
#include "zbuf.h"

/* Forward. */

static nmsg_buf input_open(nmsg_buf_type, int);
static nmsg_res read_buf(nmsg_buf, ssize_t, ssize_t);
static nmsg_res read_buf_oneshot(nmsg_buf, ssize_t, ssize_t);
static nmsg_res read_frag_buf(nmsg_buf, ssize_t, Nmsg__Nmsg **);
static nmsg_res read_header(nmsg_buf, ssize_t *);
static nmsg_res reassemble_frags(nmsg_buf, Nmsg__Nmsg **, struct nmsg_frag *);
static void free_frags(nmsg_buf);
static void gc_frags(nmsg_buf);

/* Red-black nmsg_frag glue. */

static int
frag_cmp(struct nmsg_frag *e1, struct nmsg_frag *e2) {
	return (e2->id - e1->id);
}

RB_PROTOTYPE(frag_ent, nmsg_frag, link, frag_cmp);
RB_GENERATE(frag_ent, nmsg_frag, link, frag_cmp);

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
	assert((*buf)->type == nmsg_buf_type_read_file ||
	       (*buf)->type == nmsg_buf_type_read_sock);
	nmsg_zbuf_destroy(&(*buf)->zb);
	free_frags(*buf);
	nmsg_buf_destroy(buf);
	return (nmsg_res_success);
}

nmsg_res
nmsg_input_next(nmsg_buf buf, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail, msgsize;

	/* read the header */
	res = read_header(buf, &msgsize);
	if (res != nmsg_res_success)
		return (res);

	/* if the buf is a file buf, read the nmsg container */
	bytes_avail = nmsg_buf_avail(buf);
	if (buf->type == nmsg_buf_type_read_file && bytes_avail < msgsize) {
		ssize_t bytes_to_read = msgsize - bytes_avail;
		read_buf(buf, bytes_to_read, bytes_to_read);
	}
	/* if the buf is a sock buf, then the entire message must have been
	 * read by the call to read_header() */
	else if (buf->type == nmsg_buf_type_read_sock)
		assert(nmsg_buf_avail(buf) == msgsize);

	/* unpack message */
	if (buf->flags & NMSG_FLAG_FRAGMENT) {
		res = read_frag_buf(buf, msgsize, nmsg);
	} else if (buf->flags & NMSG_FLAG_ZLIB) {
		size_t ulen;
		u_char *ubuf;

		res = nmsg_zbuf_inflate(buf->zb, msgsize, buf->pos,
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

	/* if the buf is a sock buf, then expire old outstanding fragments */
	if (buf->type == nmsg_buf_type_read_sock &&
	    buf->rbuf.nfrags > 0 &&
	    buf->rbuf.ts.tv_sec - buf->rbuf.lastgc.tv_sec >=
		NMSG_FRAG_GC_INTERVAL)
	{
		gc_frags(buf);
		buf->rbuf.lastgc = buf->rbuf.ts;
	}

	return (res);
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
	buf->zb = nmsg_zbuf_inflate_init();
	if (buf->zb == NULL) {
		nmsg_buf_destroy(&buf);
		return (NULL);
	}
	RB_INIT(&buf->rbuf.nft.head);
	return (buf);
}

static nmsg_res
read_header(nmsg_buf buf, ssize_t *msgsize) {
	bool reset_buf = false;
	static char magic[] = NMSG_MAGIC;
	ssize_t bytes_avail, bytes_needed, lenhdrsz;
	nmsg_res res = nmsg_res_failure;
	uint16_t vers;

	/* initialize *msgsize */
	*msgsize = 0;

	/* ensure we have the (magic, version) header */
	bytes_avail = nmsg_buf_avail(buf);
	if (bytes_avail < NMSG_HDRSZ) {
		if (buf->type == nmsg_buf_type_read_file) {
			assert(bytes_avail >= 0);
			bytes_needed = NMSG_HDRSZ - bytes_avail;
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
			res = read_buf_oneshot(buf, NMSG_HDRSZ, buf->bufsz);
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

	/* ensure we have the length header */
	bytes_avail = nmsg_buf_avail(buf);
	if (vers == 1U) {
		lenhdrsz = NMSG_LENHDRSZ_V1;
	} else if ((vers & 0xFF) == 2U) {
		buf->flags = vers >> 8;
		vers &= 0xFF;
		lenhdrsz = NMSG_LENHDRSZ_V2;
	} else {
		res = nmsg_res_version_mismatch;
		goto read_header_out;
	}
	if (bytes_avail < lenhdrsz) {
		if (reset_buf || bytes_avail == 0)
			buf->end = buf->pos = buf->data;
		bytes_needed = lenhdrsz - bytes_avail;
		if (buf->type == nmsg_buf_type_read_file) {
			if (bytes_avail == 0) {
				res = read_buf(buf, bytes_needed, buf->bufsz);
			} else {
				res = read_buf(buf, bytes_needed, bytes_needed);
				reset_buf = true;
			}
		} else if (buf->type == nmsg_buf_type_read_sock) {
			/* the length header should have been read by
			 * read_buf_oneshot() above */
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
	/* reset the buffer if the header was split */
	if (reset_buf)
		buf->end = buf->pos = buf->data;

	return (res);
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
	nmsg_time_get(&buf->rbuf.ts);
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
	nmsg_time_get(&buf->rbuf.ts);
	return (nmsg_res_success);
}


#define FRAG_INSERT(buf, fent) do { \
	RB_INSERT(frag_ent, &((buf)->rbuf.nft.head), fent); \
} while(0)

#define FRAG_FIND(buf, fent, find) do { \
	fent = RB_FIND(frag_ent, &((buf)->rbuf.nft.head), find); \
} while(0)

#define FRAG_REMOVE(buf, fent) do { \
	RB_REMOVE(frag_ent, &((buf)->rbuf.nft.head), fent); \
} while(0)

#define FRAG_NEXT(buf, fent, fent_next) do { \
	fent_next = RB_NEXT(frag_ent, &((buf)->rbuf.nft.head), fent); \
} while(0)

static nmsg_res
read_frag_buf(nmsg_buf buf, ssize_t msgsize, Nmsg__Nmsg **nmsg) {
	Nmsg__NmsgFragment *nfrag;
	nmsg_res res;
	struct nmsg_frag *fent, find;

	res = nmsg_res_again;

	nfrag = nmsg__nmsg_fragment__unpack(NULL, msgsize, buf->pos);

	/* find the fragment, else allocate a node and insert into the tree */
	find.id = nfrag->id;
	FRAG_FIND(buf, fent, &find);
	if (fent == NULL) {
		fent = malloc(sizeof(*fent));
		if (fent == NULL) {
			res = nmsg_res_memfail;
			goto read_frag_buf_out;
		}
		fent->id = nfrag->id;
		fent->last = nfrag->last;
		fent->rem = nfrag->last + 1;
		fent->ts = buf->rbuf.ts;
		fent->frags = calloc(1, sizeof(ProtobufCBinaryData) *
				     (fent->last + 1));
		if (fent->frags == NULL) {
			free(fent);
			res = nmsg_res_memfail;
			goto read_frag_buf_out;
		}
		FRAG_INSERT(buf, fent);
		buf->rbuf.nfrags += 1;
	}

	if (fent->frags[nfrag->current].data != NULL) {
		/* fragment has already been received, network problem? */
		goto read_frag_buf_out;
	}

	/* attach the fragment payload to the tree node */
	fent->frags[nfrag->current] = nfrag->fragment;

	/* decrement number of remaining fragments */
	fent->rem -= 1;

	/* detach the fragment payload from the NmsgFragment */
	nfrag->fragment.len = 0;
	nfrag->fragment.data = NULL;

	/* reassemble if all the fragments have been gathered */
	if (fent->rem == 0)
		res = reassemble_frags(buf, nmsg, fent);

read_frag_buf_out:
	nmsg__nmsg_fragment__free_unpacked(nfrag, NULL);
	return (res);
}

static nmsg_res
reassemble_frags(nmsg_buf buf, Nmsg__Nmsg **nmsg, struct nmsg_frag *fent) {
	nmsg_res res;
	size_t len, padded_len;
	uint8_t *payload, *ptr;
	unsigned i;

	res = nmsg_res_again;

	/* obtain total length of reassembled payload */
	len = 0;
	for (i = 0; i <= fent->last; i++) {
		assert(fent->frags[i].data != NULL);
		len += fent->frags[i].len;
	}

	/* round total length up to nearest kilobyte */
	padded_len = len;
	if (len % 1024 != 0)
		padded_len += 1024 - (len % 1024);

	ptr = payload = malloc(padded_len);
	if (payload == NULL) {
		return (nmsg_res_memfail);
	}

	/* copy into the payload buffer and deallocate frags */
	for (i = 0; i <= fent->last; i++) {
		memcpy(ptr, fent->frags[i].data, fent->frags[i].len);
		free(fent->frags[i].data);
		ptr += fent->frags[i].len;
	}
	free(fent->frags);

	/* decompress */
	if (buf->flags & NMSG_FLAG_ZLIB) {
		size_t ulen;
		u_char *ubuf, *zbuf;

		zbuf = (u_char *) payload;
		res = nmsg_zbuf_inflate(buf->zb, len, zbuf,
					&ulen, &ubuf);
		if (res != nmsg_res_success) {
			free(payload);
			goto reassemble_frags_out;
		}
		payload = ubuf;
		len = ulen;
		free(zbuf);
	}

	/* unpack the defragmented payload */
	*nmsg = nmsg__nmsg__unpack(NULL, len, payload);
	assert(*nmsg != NULL);
	free(payload);

	res = nmsg_res_success;

reassemble_frags_out:
	/* deallocate from tree */
	buf->rbuf.nfrags -= 1;
	FRAG_REMOVE(buf, fent);
	free(fent);

	return (res);
}

static void
free_frags(nmsg_buf buf) {
	struct nmsg_frag *fent, *fent_next;
	unsigned i;

	for (fent = RB_MIN(frag_ent, &buf->rbuf.nft.head);
	     fent != NULL;
	     fent = fent_next)
	{
		FRAG_NEXT(buf, fent, fent_next);
		for (i = 0; i <= fent->last; i++)
			free(fent->frags[i].data);
		free(fent->frags);
		FRAG_REMOVE(buf, fent);
		free(fent);
	}
}

static void
gc_frags(nmsg_buf buf) {
	struct nmsg_frag *fent, *fent_next;
	unsigned i;

	for (fent = RB_MIN(frag_ent, &buf->rbuf.nft.head);
	     fent != NULL;
	     fent = fent_next)
	{
		FRAG_NEXT(buf, fent, fent_next);
		if (buf->rbuf.ts.tv_sec - fent->ts.tv_sec >=
		    NMSG_FRAG_GC_INTERVAL)
		{
			FRAG_NEXT(buf, fent, fent_next);
			for (i = 0; i <= fent->last; i++)
				free(fent->frags[i].data);
			free(fent->frags);
			FRAG_REMOVE(buf, fent);
			free(fent);
			buf->rbuf.nfrags -= 1;
		}
	}
}
