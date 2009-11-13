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

#include "nmsg_port.h"

#include <sys/time.h>
#include <sys/types.h>
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include <zlib.h>

#include "nmsg.h"

#include "msgmod_plugin.h"

/* Macros. */

#define NMSG_FRAG_GC_INTERVAL	30
#define NMSG_MSG_MODULE_PREFIX	"nmsg_msg"

/* Enums. */

typedef enum {
	nmsg_modtype_msgmod
} nmsg_modtype;

typedef enum {
	nmsg_stream_type_file,
	nmsg_stream_type_sock
} nmsg_stream_type;

typedef enum {
	nmsg_pcap_type_file,
	nmsg_pcap_type_live
} nmsg_pcap_type;

/* Forward. */

struct nmsg_buf;
struct nmsg_dlmod;
struct nmsg_frag;
struct nmsg_frag_tree;
struct nmsg_input;
struct nmsg_output;
struct nmsg_msgmod;
struct nmsg_msgmod_field;
struct nmsg_msgmod_clos;
struct nmsg_pcap;
struct nmsg_pres;
struct nmsg_stream_input;
struct nmsg_stream_output;

/* Globals. */

extern bool			_nmsg_global_autoclose;
extern int			_nmsg_global_debug;
extern struct nmsg_msgmodset *	_nmsg_global_msgmodset;

/* Function types. */

typedef nmsg_res (*nmsg_input_read_fp)(struct nmsg_input *, nmsg_message_t *);
typedef nmsg_res (*nmsg_input_read_loop_fp)(struct nmsg_input *, int,
					    nmsg_cb_message, void *);
typedef nmsg_res (*nmsg_output_write_fp)(struct nmsg_output *, nmsg_message_t);

/* Data types. */

/* nmsg_frag: used by nmsg_stream_input */
struct nmsg_frag {
	RB_ENTRY(nmsg_frag)	link;
	uint32_t		id;
	unsigned		last;
	unsigned		rem;
	struct timespec		ts;
	ProtobufCBinaryData	*frags;
};

/* nmsg_frag_tree: used by nmsg_stream_input */
struct nmsg_frag_tree {
	RB_HEAD(frag_ent, nmsg_frag)  head;
};

/* nmsg_buf: used by nmsg_stream_input, nmsg_stream_output */
struct nmsg_buf {
	int			fd;
	size_t			bufsz;
	u_char			*data;	/* allocated data starts here */
	u_char			*pos;	/* position of next buffer read */
	u_char			*end;	/* one byte beyond valid data */
};

/* nmsg_pcap: used by nmsg_input */
struct nmsg_pcap {
	int			datalink;
	pcap_t			*handle;
	struct nmsg_ipreasm	*reasm;
	u_char			*new_pkt;

	pcap_t			*user;
	char			*userbpft;
	struct bpf_program	userbpf;

	nmsg_pcap_type		type;
};

/* nmsg_pres: used by nmsg_input and nmsg_output */
struct nmsg_pres {
	pthread_mutex_t		lock;
	FILE			*fp;
	bool			flush;
	char			*endline;
};

/* nmsg_stream_input: used by nmsg_input */
struct nmsg_stream_input {
	nmsg_stream_type	type;
	struct nmsg_buf		*buf;
	Nmsg__Nmsg		*nmsg;
	unsigned		np_index;
	struct nmsg_frag_tree	nft;
	struct pollfd		pfd;
	struct timespec		now;
	struct timespec		lastgc;
	unsigned		nfrags;
	unsigned		flags;
	nmsg_zbuf_t		zb;
	u_char			*zb_tmp;
	unsigned		source;
	unsigned		operator;
	unsigned		group;
};

/* nmsg_stream_output: used by nmsg_output */
struct nmsg_stream_output {
	pthread_mutex_t		lock;
	nmsg_stream_type	type;
	struct nmsg_buf		*buf;
	Nmsg__Nmsg		*nmsg;
	size_t			estsz;
	nmsg_rate_t		rate;
	bool			buffered;
	nmsg_zbuf_t		zb;
	u_char			*zb_tmp;
	unsigned		source;
	unsigned		operator;
	unsigned		group;
};

/* nmsg_callback_output: used by nmsg_output */
struct nmsg_callback_output {
	nmsg_cb_message		cb;
	void			*user;
};

/* nmsg_input */
struct nmsg_input {
	nmsg_input_type		type;
	nmsg_msgmod_t		msgmod;
	void			*clos;
	union {
		struct nmsg_stream_input  *stream;
		struct nmsg_pcap	  *pcap;
		struct nmsg_pres	  *pres;
	};
	nmsg_input_read_fp	read_fp;
	nmsg_input_read_loop_fp	read_loop_fp;
};

/* nmsg_output */
struct nmsg_output {
	nmsg_output_type	type;
	union {
		struct nmsg_stream_output	*stream;
		struct nmsg_pres		*pres;
		struct nmsg_callback_output	*callback;
	};
	nmsg_output_write_fp	write_fp;
};

/* nmsg_message */
struct nmsg_message {
	nmsg_msgmod_t		mod;
	ProtobufCMessage	*message;
	Nmsg__NmsgPayload	*np;
};

	/**
	 * an nmsg_message MUST always have a non-NULL ->np member.
	 *
	 * it MAY have a non-NULL ->mod member, if the payload corresponds to
	 * a known message type.
	 *
	 * it MAY have a non-NULL ->message member, if the payload corresponds
	 * to a known message type, and the message module implementing that
	 * message type is a transparent message module.
	 *
	 * nmsg_input generates payloads, and wraps them in an nmsg_message.
	 * at this stage the payload ISN'T decoded, because the decoded
	 * message may not be used. (e.g., source -> sink traffic.)
	 *
	 * nmsg_output, when writing nmsg_messages, needs to synchronize the
	 * ->message object (if it is non-NULL) with the ->np object,
	 * then detach ->np so that it can be added to the output queue.
	 * if the caller wants to reuse the nmsg_message object, he needs to
	 * call another function to reinitialize ->payload.
	 */

/* dlmod / msgmod / msgmodset */

struct nmsg_dlmod {
	ISC_LINK(struct nmsg_dlmod)	link;
	nmsg_modtype			type;
	char				*path;
	void				*handle;
};

typedef enum nmsg_msgmod_clos_mode {
	nmsg_msgmod_clos_m_keyval,
	nmsg_msgmod_clos_m_multiline
} nmsg_msgmod_clos_mode;

struct nmsg_msgmod_clos {
	char			*nmsg_pbuf;
	size_t			estsz;
	nmsg_msgmod_clos_mode	mode;
	struct nmsg_msgmod_field	*field;
	struct nmsg_strbuf	*strbufs;
};

struct nmsg_msgvendor {
	struct nmsg_msgmod	**msgtypes;
	char			*vname;
	size_t			nm;
};

struct nmsg_msgmod {
	struct nmsg_msgmod_plugin	*plugin;
	struct nmsg_msgmod_field	*fields;
	size_t				n_fields;
};

struct nmsg_msgmodset {
	ISC_LIST(struct nmsg_dlmod)	dlmods;
	struct nmsg_msgvendor		**vendors;
	size_t				nv;
};

/* Prototypes. */

/* from alias.c */

nmsg_res		_nmsg_alias_init(void);
void			_nmsg_alias_fini(void);

/* from buf.c */

ssize_t			_nmsg_buf_avail(struct nmsg_buf *buf);
ssize_t			_nmsg_buf_used(struct nmsg_buf *buf);
struct nmsg_buf *	_nmsg_buf_new(size_t sz);
void			_nmsg_buf_destroy(struct nmsg_buf **buf);
void			_nmsg_buf_reset(struct nmsg_buf *buf);

/* from dlmod.c */

struct nmsg_dlmod *	_nmsg_dlmod_init(const char *path);
void			_nmsg_dlmod_destroy(struct nmsg_dlmod **dlmod);

/* from msgmod.c */

struct nmsg_msgmod *	_nmsg_msgmod_start(struct nmsg_msgmod_plugin *plugin);
void			_nmsg_msgmod_stop(struct nmsg_msgmod **mod);

/* from message.c */

nmsg_res		_nmsg_message_init_message(struct nmsg_message *msg);
nmsg_res		_nmsg_message_init_payload(struct nmsg_message *msg);
nmsg_res		_nmsg_message_deserialize(struct nmsg_message *msg);
nmsg_res		_nmsg_message_serialize(struct nmsg_message *msg);
nmsg_message_t		_nmsg_message_from_payload(Nmsg__NmsgPayload *np);


/* from msgmodset.c */

struct nmsg_msgmodset *	_nmsg_msgmodset_init(const char *path);
void			_nmsg_msgmodset_destroy(struct nmsg_msgmodset **);

/* from payload.c */
void			_nmsg_payload_free(Nmsg__NmsgPayload **np);
size_t			_nmsg_payload_size(const Nmsg__NmsgPayload *np);

#endif /* NMSG_PRIVATE_H */
