/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
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
#include <assert.h>
#include <stdlib.h>

#include <zlib.h>

#include "nmsg.h"
#include "private.h"

/* Private declarations. */

typedef enum nmsg_zbuf_type {
	nmsg_zbuf_type_deflate,
	nmsg_zbuf_type_inflate
} nmsg_zbuf_type;

struct nmsg_zbuf {
	nmsg_zbuf_type		type;
	z_stream		zs;
};

/* Export. */

nmsg_zbuf
nmsg_zbuf_deflate_init(void) {
	int zret;
	struct nmsg_zbuf *zb;

	zb = malloc(sizeof(*zb));
	if (zb == NULL)
		return (NULL);

	zb->type = nmsg_zbuf_type_deflate;
	zb->zs.zalloc = Z_NULL;
	zb->zs.zfree = Z_NULL;
	zb->zs.opaque = Z_NULL;

	zret = deflateInit(&zb->zs, Z_DEFAULT_COMPRESSION);
	if (zret != Z_OK) {
		free(zb);
		return (NULL);
	}

	return (zb);
}

nmsg_zbuf
nmsg_zbuf_inflate_init(void) {
	int zret;
	struct nmsg_zbuf *zb;

	zb = malloc(sizeof(*zb));
	if (zb == NULL)
		return (NULL);

	zb->type = nmsg_zbuf_type_inflate;
	zb->zs.zalloc = Z_NULL;
	zb->zs.zfree = Z_NULL;
	zb->zs.opaque = Z_NULL;
	zb->zs.avail_in = 0;
	zb->zs.next_in = Z_NULL;

	zret = inflateInit(&zb->zs);
	if (zret != Z_OK) {
		free(zb);
		return (NULL);
	}

	return (zb);
}

void
nmsg_zbuf_destroy(nmsg_zbuf *zb) {
	if (*zb != NULL) {
		if ((*zb)->type == nmsg_zbuf_type_deflate)
			deflateEnd(&(*zb)->zs);
		else if ((*zb)->type == nmsg_zbuf_type_inflate)
			inflateEnd(&(*zb)->zs);
		free(*zb);
		*zb = NULL;
	}
}

nmsg_res
nmsg_zbuf_deflate(nmsg_zbuf zb, size_t len, u_char *buf,
		  size_t *zlen, u_char *zbuf)
{
	int zret;
	uint32_t *zbuf_origlen = (uint32_t *) zbuf;

	*zbuf_origlen = htonl(len);
	zbuf += sizeof(*zbuf_origlen);

	zb->zs.avail_in = len;
	zb->zs.next_in = buf;
	zb->zs.avail_out = *zlen;
	zb->zs.next_out = zbuf;

	zret = deflate(&zb->zs, Z_FINISH);
	assert(zret == Z_STREAM_END);
	assert(zb->zs.avail_in == 0);
	*zlen = *zlen - zb->zs.avail_out + sizeof(*zbuf_origlen);
	assert(deflateReset(&zb->zs) == Z_OK);
	assert(*zlen > 0);

	return (nmsg_res_success);
}

nmsg_res
nmsg_zbuf_inflate(nmsg_zbuf zb, size_t zlen, u_char *zbuf,
		  size_t *ulen, u_char **ubuf)
{
	int zret;

	*ulen = ntohl(*((uint32_t *) zbuf));
	zbuf += sizeof(uint32_t);

	*ubuf = malloc(*ulen);
	if (*ubuf == NULL)
		return (nmsg_res_memfail);

	zb->zs.avail_in = zlen;
	zb->zs.next_in = zbuf;
	zb->zs.avail_out = *ulen;
	zb->zs.next_out = *ubuf;

	zret = inflate(&zb->zs, Z_NO_FLUSH);
	if (zret != Z_STREAM_END || zb->zs.avail_out != 0) {
		free(*ubuf);
		return (nmsg_res_failure);
	}
	assert(inflateReset(&zb->zs) == Z_OK);

	return (nmsg_res_success);
}
