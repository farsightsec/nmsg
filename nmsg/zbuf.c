/*
 * Copyright (c) 2009, 2011, 2012 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

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

nmsg_zbuf_t
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

nmsg_zbuf_t
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
nmsg_zbuf_destroy(nmsg_zbuf_t *zb) {
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
nmsg_zbuf_deflate(nmsg_zbuf_t zb, size_t len, u_char *buf,
		  size_t *z_len, u_char *z_buf)
{
	int zret;

	store_net32(z_buf, (uint32_t) len);
	z_buf += 4;

	zb->zs.avail_in = len;
	zb->zs.next_in = buf;
	zb->zs.avail_out = *z_len;
	zb->zs.next_out = z_buf;

	zret = deflate(&zb->zs, Z_FINISH);
	assert(zret == Z_STREAM_END);
	assert(zb->zs.avail_in == 0);
	*z_len = *z_len - zb->zs.avail_out + sizeof(uint32_t);
	zret = deflateReset(&zb->zs);
	assert(zret == Z_OK);
	assert(*z_len > 0);

	return (nmsg_res_success);
}

nmsg_res
nmsg_zbuf_inflate(nmsg_zbuf_t zb, size_t z_len, u_char *z_buf,
		  size_t *u_len, u_char **u_buf)
{
	int zret;
	uint32_t my_ulen;

	load_net32(z_buf, &my_ulen);
	z_buf += 4;
	*u_len = my_ulen;

	*u_buf = malloc(*u_len);
	if (*u_buf == NULL)
		return (nmsg_res_memfail);

	zb->zs.avail_in = z_len;
	zb->zs.next_in = z_buf;
	zb->zs.avail_out = *u_len;
	zb->zs.next_out = *u_buf;

	zret = inflate(&zb->zs, Z_NO_FLUSH);
	if (zret != Z_STREAM_END || zb->zs.avail_out != 0) {
		free(*u_buf);
		return (nmsg_res_failure);
	}
	zret = inflateReset(&zb->zs);
	assert(zret == Z_OK);

	return (nmsg_res_success);
}
