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

#ifndef NMSG_PRIVATE_H
#define NMSG_PRIVATE_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/private.h
 * \brief Private nmsg data types and functions.
 */

/***
 *** Imports
 ***/

#include "nmsg_port.h"

#include <sys/types.h>
#include <poll.h>
#include <stdint.h>
#include <time.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include <zlib.h>

#include "nmsg.h"
#include "rate.h"
#include "tree.h"

/***
 *** Types
 ***/

typedef enum {
	nmsg_modtype_pbuf
} nmsg_modtype;

typedef enum {
	nmsg_buf_type_read_file,
	nmsg_buf_type_read_sock,
	nmsg_buf_type_write_file,
	nmsg_buf_type_write_sock
} nmsg_buf_type;

typedef enum {
	nmsg_pres_type_read,
	nmsg_pres_type_write
} nmsg_pres_type;

struct nmsg_frag {
	RB_ENTRY(nmsg_frag)	link;
	uint32_t		id;
	unsigned		last;
	unsigned		rem;
	struct timespec		ts;
	ProtobufCBinaryData	*frags;
};

struct nmsg_frag_tree {
	RB_HEAD(frag_ent, nmsg_frag)  head;
};

struct nmsg_rbuf {
	struct pollfd		pfd;
	struct nmsg_frag_tree	nft;
	struct timespec		ts;
};

struct nmsg_wbuf {
	Nmsg__Nmsg		*nmsg;
	size_t			estsz;
	nmsg_rate		rate;
};

struct nmsg_buf {
	int			fd;
	size_t			bufsz;
	u_char			*pos, *end, *data;
	nmsg_buf_type		type;
	union {
		struct nmsg_wbuf  wbuf;
		struct nmsg_rbuf  rbuf;
	};
	uint8_t			flags;
	nmsg_zbuf		zb;
	u_char			*zb_tmp;
};

struct nmsg_pres {
	bool			flush;
	int			fd;
	nmsg_pres_type		type;
	unsigned		vid;
	unsigned		msgtype;
};

struct nmsg_dlmod {
	ISC_LINK(struct nmsg_dlmod)	link;
	nmsg_modtype			type;
	char				*path;
	void				*handle;
	void				*ctx;
};

struct nmsg_vid_msgtype {
	struct nmsg_pbmod		**v_pbmods;
	unsigned			nm;
};

typedef enum nmsg_zbuf_type {
	nmsg_zbuf_type_deflate,
	nmsg_zbuf_type_inflate
} nmsg_zbuf_type;

struct nmsg_zbuf {
	nmsg_zbuf_type		type;
	z_stream		zs;
};

/***
 *** Functions
 ***/

nmsg_buf
nmsg_buf_new(nmsg_buf_type type, size_t sz);

ssize_t
nmsg_buf_used(nmsg_buf buf);

ssize_t
nmsg_buf_avail(nmsg_buf buf);

void
nmsg_buf_destroy(nmsg_buf *buf);

struct nmsg_dlmod *
nmsg_dlmod_init(const char *path);

void
nmsg_dlmod_destroy(struct nmsg_dlmod **dlmod);

#endif /* NMSG_PRIVATE_H */
