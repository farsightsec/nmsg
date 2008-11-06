#ifndef NMSG_PRIVATE_H
#define NMSG_PRIVATE_H

#include <sys/types.h>
#include <poll.h>

#include <nmsg.h>
#include <nmsg/protobuf-c.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

typedef enum {
	nmsg_modtype_pbuf
} nmsg_modtype;

typedef enum {
	nmsg_buf_type_read,
	nmsg_buf_type_write_file,
	nmsg_buf_type_write_sock
} nmsg_buf_type;

typedef enum {
	nmsg_pres_type_read,
	nmsg_pres_type_write
} nmsg_pres_type;

struct nmsg_rbuf {
	struct pollfd		pfd;
};

struct nmsg_wbuf {
	Nmsg__Nmsg		*nmsg;
	size_t			estsz;
	ProtobufCAllocator	*ca;
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
};

struct nmsg_pres {
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

nmsg_buf
nmsg_buf_new(nmsg_buf_type, size_t sz);

nmsg_res
nmsg_buf_ensure(nmsg_buf, ssize_t bytes);

nmsg_res
nmsg_buf_fill(nmsg_buf);

ssize_t
nmsg_buf_bytes(nmsg_buf);

ssize_t
nmsg_buf_avail(nmsg_buf);

void
nmsg_buf_destroy(nmsg_buf *);

struct nmsg_dlmod *
nmsg_dlmod_open(const char *path);

void
nmsg_dlmod_destroy(struct nmsg_dlmod **);

#endif
