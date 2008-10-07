#ifndef NMSG_PRIVATE_H
#define NMSG_PRIVATE_H

#include <stddef.h>

#include <nmsg.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

struct nmsg_wbuf {
	Nmsg__Nmsg *	nmsg;
	size_t		estsz;
};

struct nmsg_buf {
	int		fd;
	size_t		bufsz;
	u_char *	pos;
	u_char *	end;
	u_char *	data;
	nmsg_buf_type	type;
	union {
		struct nmsg_wbuf  wbuf;
	};
};

extern nmsg_buf nmsg_buf_new(nmsg_buf_type type, size_t sz);
extern nmsg_res nmsg_buf_ensure(nmsg_buf buf, ssize_t bytes);
extern nmsg_res nmsg_buf_fill(nmsg_buf buf);
extern ssize_t nmsg_buf_bytes(nmsg_buf buf);
extern ssize_t nmsg_buf_avail(nmsg_buf buf);

typedef nmsg_res (*nmsg_pbmod_init)(void);
typedef nmsg_res (*nmsg_pbmod_fini)(void);

struct nmsg_pbmod {
	int			pbmver;
	unsigned		vendor;
	nmsg_pbmod_init		init;
	nmsg_pbmod_fini		fini;
};

struct nmsg_dlmod {
	ISC_LINK(struct nmsg_dlmod)  link;
	const char *		path;
	void *			handle;
};

struct nmsg_pbmodset {
	ISC_LIST(struct nmsg_dlmod)  dlmods;
	struct nmsg_pbmod **	pbmods;
};

#endif
