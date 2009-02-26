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
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include <pcap.h>
#include <zlib.h>

#include "nmsg.h"
#include "ipreasm.h"
#include "rate.h"
#include "tree.h"

/***
 *** Macros
 ***/

#define NMSG_FRAG_GC_INTERVAL	30

/***
 *** Types
 ***/

typedef enum {
	nmsg_modtype_pbuf
} nmsg_modtype;

typedef enum {
	nmsg_buf_type_read_file,
	nmsg_buf_type_read_sock,
	nmsg_buf_type_read_pcap,
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
	struct timespec		ts, lastgc;
	unsigned		nfrags;
};

struct nmsg_wbuf {
	Nmsg__Nmsg		*nmsg;
	size_t			estsz;
	nmsg_rate		rate;
	bool			buffered;
};

struct nmsg_pcap {
	int			datalink;
	pcap_t			*handle;
	struct reasm_ip		*reasm;
};

struct nmsg_buf {
	int			fd;
	size_t			bufsz;
	u_char			*pos, *end, *data;
	nmsg_buf_type		type;
	uint8_t			flags;
	nmsg_zbuf		zb;
	u_char			*zb_tmp;
	union {
		struct nmsg_wbuf  wbuf;
		struct nmsg_rbuf  rbuf;
		struct nmsg_pcap  pcap;
	};
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

typedef enum nmsg_pbmod_clos_mode {
	nmsg_pbmod_clos_m_keyval,
	nmsg_pbmod_clos_m_multiline
} nmsg_pbmod_clos_mode;

struct nmsg_pbmod_clos {
	char			*nmsg_pbuf;
	size_t			estsz;
	nmsg_pbmod_clos_mode	mode;
	struct nmsg_pbmod_field	*field;
	struct nmsg_strbuf	*strbufs;
};

/***
 *** Functions
 ***/

nmsg_buf nmsg_buf_new(nmsg_buf_type type, size_t sz);

ssize_t nmsg_buf_used(nmsg_buf buf);

ssize_t nmsg_buf_avail(nmsg_buf buf);

void nmsg_buf_destroy(nmsg_buf *buf);

struct nmsg_dlmod *nmsg_dlmod_init(const char *path);

void nmsg_dlmod_destroy(struct nmsg_dlmod **dlmod);

nmsg_res _nmsg_pbmod_start(struct nmsg_pbmod *mod);

#endif /* NMSG_PRIVATE_H */
