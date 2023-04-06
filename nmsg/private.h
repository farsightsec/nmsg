/*
 * Copyright (c) 2008-2015, 2019 by Farsight Security, Inc.
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

#ifndef NMSG_PRIVATE_H
#define NMSG_PRIVATE_H

#include "nmsg_port_net.h"

#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else
# ifdef HAVE_SYS_ENDIAN_H
#  include <sys/endian.h>
# endif
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <zlib.h>

#include <protobuf-c/protobuf-c.h>

#ifdef HAVE_LIBZMQ
# include <zmq.h>
#endif /* HAVE_LIBZMQ */

#ifdef HAVE_YAJL
#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#endif /* HAVE_YAJL */

#include "nmsg.h"
#include "nmsg.pb-c.h"

#include "fltmod_plugin.h"
#include "msgmod_plugin.h"
#include "ipreasm.h"

#include "libmy/crc32c.h"
#include "libmy/list.h"
#include "libmy/tree.h"
#include "libmy/ubuf.h"
#include "libmy/b64_decode.h"
#include "libmy/b64_encode.h"
#include "libmy/vector.h"

/* Macros. */

#define STR(x) #x
#define XSTR(x) STR(x)

#define NMSG_SEQSRC_GC_INTERVAL	120
#define NMSG_FRAG_GC_INTERVAL	30
#define NMSG_NSEC_PER_SEC	1000000000

#define DEFAULT_STRBUF_ALLOC_SZ		16384

#define NMSG_FLT_MODULE_PREFIX	"nmsg_flt" XSTR(NMSG_FLTMOD_VERSION)
#define NMSG_MSG_MODULE_PREFIX	"nmsg_msg" XSTR(NMSG_MSGMOD_VERSION)

#define NMSG_MODULE_SUFFIX	".so"

#define _nmsg_dprintf(level, format, ...) \
do { \
	if (_nmsg_global_debug >= (level)) \
		fprintf(stderr, format, ##__VA_ARGS__); \
} while (0)

#define _nmsg_dprintfv(var, level, format, ...) \
do { \
	if ((var) >= (level)) \
		fprintf(stderr, format, ##__VA_ARGS__); \
} while (0)

/* Enums. */

typedef enum {
	nmsg_stream_type_file,
	nmsg_stream_type_sock,
	nmsg_stream_type_zmq,
	nmsg_stream_type_null,
} nmsg_stream_type;

/* Forward. */

struct nmsg_brate;
struct nmsg_buf;
struct nmsg_container;
struct nmsg_dlmod;
struct nmsg_frag;
struct nmsg_frag_key;
struct nmsg_frag_tree;
struct nmsg_input;
struct nmsg_json;
struct nmsg_output;
struct nmsg_msgmod;
struct nmsg_msgmod_field;
struct nmsg_msgmod_clos;
struct nmsg_pcap;
struct nmsg_pres;
struct nmsg_stream_input;
struct nmsg_stream_output;
struct nmsg_seqsrc;
struct nmsg_seqsrc_key;

/* Globals. */

extern bool			_nmsg_global_autoclose;
extern int			_nmsg_global_debug;
extern struct nmsg_msgmodset *	_nmsg_global_msgmodset;

/* Function types. */

typedef nmsg_res (*nmsg_input_read_fp)(struct nmsg_input *, nmsg_message_t *);
typedef nmsg_res (*nmsg_input_read_loop_fp)(struct nmsg_input *, int,
					    nmsg_cb_message, void *);
typedef nmsg_res (*nmsg_input_stream_read_fp)(struct nmsg_input *, Nmsg__Nmsg **);
typedef nmsg_res (*nmsg_output_write_fp)(struct nmsg_output *, nmsg_message_t);
typedef nmsg_res (*nmsg_output_flush_fp)(struct nmsg_output *);

/* Data types. */

/* nmsg_seqsrc */
struct nmsg_seqsrc_key {
	uint64_t			sequence_id;
	sa_family_t			af;
	uint16_t			port;
	union {
		uint8_t			ip4[4];
		uint8_t			ip6[16];
	};
};

struct nmsg_seqsrc {
	ISC_LINK(struct nmsg_seqsrc)	link;
	struct nmsg_seqsrc_key		key;
	uint32_t			sequence;
	uint64_t			sequence_id;
	uint64_t			count;
	uint64_t			count_dropped;
	time_t				last;
	bool				init;
	char				addr_str[INET6_ADDRSTRLEN];
};

/* nmsg_frag: used by nmsg_stream_input */
struct nmsg_frag_key {
	uint32_t		id;
	uint32_t		crc;
	struct sockaddr_storage	addr_ss;
};

struct nmsg_frag {
	RB_ENTRY(nmsg_frag)	link;
	struct nmsg_frag_key	key;
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
	struct _nmsg_ipreasm	*reasm;
	u_char			*new_pkt;

	pcap_t			*user;
	char			*userbpft;
	struct bpf_program	userbpf;

	nmsg_pcap_type		type;
	bool			raw;
};

/* nmsg_pres: used by nmsg_input and nmsg_output */
struct nmsg_pres {
	pthread_mutex_t		lock;
	FILE			*fp;
	bool			flush;
	char			*endline;
};

/* nmsg_json: used by nmsg_input and nmsg_output */
struct nmsg_json {
#ifdef HAVE_YAJL
#endif /* HAVE_YAJL */
	pthread_mutex_t		lock;
	FILE			*fp;
	int			orig_fd;
	bool			flush;
};

/* nmsg_stream_input: used by nmsg_input */
struct nmsg_stream_input {
	nmsg_stream_type	type;
	struct nmsg_buf		*buf;
#ifdef HAVE_LIBZMQ
	void			*zmq;
#endif /* HAVE_LIBZMQ */
	Nmsg__Nmsg		*nmsg;
	unsigned		np_index;
	size_t			nc_size;
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
	bool			blocking_io;
	bool			verify_seqsrc;
	struct nmsg_brate	*brate;
	ISC_LIST(struct nmsg_seqsrc)  seqsrcs;
	struct sockaddr_storage	addr_ss;
	uint64_t		count_recv;
	uint64_t		count_drop;

	nmsg_input_stream_read_fp  stream_read_fp;
};

/* nmsg_stream_output: used by nmsg_output */
struct nmsg_stream_output {
	pthread_mutex_t		c_lock;			/* Container lock. */
	pthread_mutex_t		w_lock;			/* Write/Send lock. */
	nmsg_stream_type	type;
	int			fd;
#ifdef HAVE_LIBZMQ
	void			*zmq;
#endif /* HAVE_LIBZMQ */
	nmsg_container_t	c;
	size_t			bufsz;
	nmsg_random_t		random;
	nmsg_rate_t		rate;
	bool			buffered;
	unsigned		source;
	unsigned		operator;
	unsigned		group;
	bool			do_zlib;
	bool			do_sequence;
	uint32_t		sequence;
	uint64_t		sequence_id;
};

/* nmsg_callback_output: used by nmsg_output */
struct nmsg_callback_output {
	nmsg_cb_message		cb;
	void			*user;
};

/* nmsg_callback_input: used by nmsg_input */
struct nmsg_callback_input {
	nmsg_cb_message_read	cb;
	void			*user;
};

/* nmsg_input */
struct nmsg_input {
	nmsg_input_type		type;
	nmsg_msgmod_t		msgmod;
	void			*clos;
	union {
		struct nmsg_stream_input	*stream;
		struct nmsg_pcap		*pcap;
		struct nmsg_pres		*pres;
		struct nmsg_json		*json;
		struct nmsg_callback_input	*callback;
	};
	nmsg_input_read_fp	read_fp;
	nmsg_input_read_loop_fp	read_loop_fp;

	bool			do_filter;
	unsigned		filter_vid;
	unsigned		filter_msgtype;
	volatile bool		stop;
};

/* nmsg_output */
struct nmsg_output {
	nmsg_output_type	type;
	union {
		struct nmsg_stream_output	*stream;
		struct nmsg_pres		*pres;
		struct nmsg_json		*json;
		struct nmsg_callback_output	*callback;
	};
	nmsg_output_write_fp	write_fp;
	nmsg_output_flush_fp	flush_fp;

	bool			do_filter;
	unsigned		filter_vid;
	unsigned		filter_msgtype;
	volatile bool		stop;
};

/* nmsg_message */
struct nmsg_message {
	nmsg_msgmod_t		mod;
	ProtobufCMessage	*message;
	Nmsg__NmsgPayload	*np;
	void			*msg_clos;
	size_t			n_allocs;
	void			**allocs;
	bool			updated;
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
	 * call another function to reinitialize ->np.
	 *
	 * note that the ->message field is not filled in (deserialized from
	 * ->np) until a function that needs to touch the ->message field is
	 * called.  if ->message is NULL when nmsg_output_write() is called
	 * on a message object, then both ->message and ->np will become NULL
	 * and the message object is invalid and should be destroyed.
	 */

/* dlmod / msgmod / msgmodset */

struct nmsg_dlmod {
	ISC_LINK(struct nmsg_dlmod)	link;
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
	void			*mod_clos;
};

struct nmsg_msgvendor {
	struct nmsg_msgmod	**msgtypes;
	char			*vname;
	size_t			nm;
};

struct nmsg_msgmod {
	struct nmsg_msgmod_plugin	*plugin;
	struct nmsg_msgmod_field	*fields;
	struct nmsg_msgmod_field	**fields_idx;
	size_t				n_fields;
};

struct nmsg_msgmodset {
	ISC_LIST(struct nmsg_dlmod)	dlmods;
	struct nmsg_msgvendor		**vendors;
	size_t				nv;
};

/* internal nmsg_strbuf wrapper to use expensive stack allocation by default */
struct nmsg_strbuf_storage {
	struct				nmsg_strbuf sb;
	char				fixed[DEFAULT_STRBUF_ALLOC_SZ];
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
nmsg_message_t		_nmsg_message_dup(struct nmsg_message *msg);
nmsg_res		_nmsg_message_dup_protobuf(const struct nmsg_message *msg, ProtobufCMessage **dst);
nmsg_res		_nmsg_message_to_json(nmsg_message_t msg, struct nmsg_strbuf *sb);

/* from msgmodset.c */

struct nmsg_msgmodset *	_nmsg_msgmodset_init(const char *path);
void			_nmsg_msgmodset_destroy(struct nmsg_msgmodset **);

/* from strbuf.c */
struct nmsg_strbuf *	_nmsg_strbuf_init(struct nmsg_strbuf_storage *sbs);
void			_nmsg_strbuf_destroy(struct nmsg_strbuf_storage *sbs);
nmsg_res		_nmsg_strbuf_expand(struct nmsg_strbuf *sb, size_t size);
char *			_nmsg_strbuf_detach(struct nmsg_strbuf *size);

/* from payload.c */
void			_nmsg_payload_free_all(Nmsg__Nmsg *nc);
void			_nmsg_payload_calc_crcs(Nmsg__Nmsg *nc);
void			_nmsg_payload_free(Nmsg__NmsgPayload **np);
size_t			_nmsg_payload_size(const Nmsg__NmsgPayload *np);

/* from input_frag.c */
nmsg_res		_input_frag_read(nmsg_input_t, Nmsg__Nmsg **, uint8_t *buf, size_t buf_len);
void			_input_frag_destroy(struct nmsg_stream_input *);
void			_input_frag_gc(struct nmsg_stream_input *);

/* from input_nmsg.c */
bool			_input_nmsg_filter(nmsg_input_t, unsigned, Nmsg__NmsgPayload *);
nmsg_res		_input_nmsg_read(nmsg_input_t, nmsg_message_t *);
nmsg_res		_input_nmsg_loop(nmsg_input_t, int, nmsg_cb_message, void *);
nmsg_res		_input_nmsg_unpack_container(nmsg_input_t, Nmsg__Nmsg **, uint8_t *, size_t);
nmsg_res		_input_nmsg_unpack_container2(const uint8_t *, size_t, unsigned, Nmsg__Nmsg **);
nmsg_res		_input_nmsg_read_container_file(nmsg_input_t, Nmsg__Nmsg **);
nmsg_res		_input_nmsg_read_container_sock(nmsg_input_t, Nmsg__Nmsg **);
#ifdef HAVE_LIBZMQ
nmsg_res		_input_nmsg_read_container_zmq(nmsg_input_t, Nmsg__Nmsg **);
#endif /* HAVE_LIBZMQ */
nmsg_res		_input_nmsg_deserialize_header(const uint8_t *, size_t, ssize_t *, unsigned *);

/* from input_callback.c */
nmsg_res		_input_nmsg_read_callback(nmsg_input_t, nmsg_message_t *);

/* from input_nullnmsg.c */
nmsg_res		_input_nmsg_read_null(nmsg_input_t, nmsg_message_t *);
nmsg_res		_input_nmsg_loop_null(nmsg_input_t, int, nmsg_cb_message, void *);

/* from input_pcap.c */
nmsg_res		_input_pcap_read(nmsg_input_t, nmsg_message_t *);
nmsg_res		_input_pcap_read_raw(nmsg_input_t, nmsg_message_t *);

/* from input_pres.c */
nmsg_res		_input_pres_read(nmsg_input_t, nmsg_message_t *);

/* from input_json.c */
nmsg_res		_input_json_read(nmsg_input_t, nmsg_message_t *);

/* from input_seqsrc.c */
struct nmsg_seqsrc *	_input_seqsrc_get(nmsg_input_t, Nmsg__Nmsg *);
void			_input_seqsrc_destroy(nmsg_input_t);
size_t			_input_seqsrc_update(nmsg_input_t, struct nmsg_seqsrc *, Nmsg__Nmsg *);

/* from output.c */
void			_output_stop(nmsg_output_t);

/* from output_nmsg.c */
nmsg_res		_output_nmsg_flush(nmsg_output_t);
nmsg_res		_output_nmsg_write(nmsg_output_t, nmsg_message_t);

/* from output_pres.c */
nmsg_res		_output_pres_write(nmsg_output_t, nmsg_message_t);

/* from output_json.c */
nmsg_res		_output_json_write(nmsg_output_t, nmsg_message_t);

/* from brate.c */
struct nmsg_brate *	_nmsg_brate_init(size_t target_byte_rate);
void			_nmsg_brate_destroy(struct nmsg_brate **);
void			_nmsg_brate_sleep(struct nmsg_brate *, size_t container_sz, size_t n_payloads, size_t n);

/* from ipdg.c */

/**
 * Parse IP datagrams from the network layer, performing reassembly if
 * necessary.
 *
 * Populate a struct nmsg_ipdg indicating where the network, transport, and
 * payload sections of the datagram are and the length of the remaining packet
 * at each of those sections.
 *
 * This function operates on datagrams from the network layer.
 *
 * Broken packets are discarded. All but the final fragment of a fragmented
 * datagram are stored internally and #nmsg_res_again is returned.
 *
 * Calling this function with the last four parameters set to NULL or 0 is
 * equivalent to calling nmsg_ipdg_parse().
 *
 * \param[out] dg caller-allocated struct nmsg_ipdg which will be populated
 *	after a successful call.
 *
 * \param[in] etype ETHERTYPE_* value. The only supported values are
 *	ETHERTYPE_IP and ETHERTYPE_IPV6.
 *
 * \param[in] len length of the packet.
 *
 * \param[in] pkt pointer to the packet.
 *
 * \param[in] reasm caller-initialized struct nmsg_ipreasm object.
 *
 * \param[in,out] new_len length of 'new_pkt'. If IP reassembly is performed,
 *	its value after return is the length of the reassembled IP datagram
 *	stored in 'new_pkt'.
 *
 * \param[out] new_pkt buffer of at least '*new_len' bytes where a
 *	reassembled IP datagram will be stored if reassembly is performed.
 *
 * \param[in] 'timestamp' arbitrary timestamp, such as seconds since the unix
 *	epoch.
 *
 * \param[out] defrag NULL, or a pointer to where the value 1 will be stored if
 *	successful defragmentation occurs.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_again
 */
nmsg_res
_nmsg_ipdg_parse_reasm(struct nmsg_ipdg *dg, unsigned etype, size_t len,
		       const u_char *pkt, struct _nmsg_ipreasm *reasm,
		       unsigned *new_len, u_char *new_pkt, int *defrag,
		       uint64_t timestamp);

#endif /* NMSG_PRIVATE_H */
