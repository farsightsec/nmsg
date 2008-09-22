#ifndef NMSG_PRIVATE_H
#define NMSG_PRIVATE_H

#include <stddef.h>

#include <nmsg.h>

#define nmsg_msgsize	8192
#define nmsg_rbufsize	(2 * nmsg_msgsize)
#define nmsg_wbufsize	(nmsg_msgsize)

struct nmsg_buf {
	nmsg_buf_type	type;
	int		fd;
	u_char		*buf_pos;
	u_char		*buf_end;
	u_char		*data;
};

extern nmsg_buf nmsg_buf_new(nmsg_buf_type type, size_t sz);
extern nmsg_res nmsg_buf_ensure(nmsg_buf buf, ssize_t bytes);
extern nmsg_res nmsg_buf_fill(nmsg_buf buf);
extern ssize_t nmsg_buf_bytes_avail(nmsg_buf buf);
extern void nmsg_buf_destroy(nmsg_buf *buf);

#endif
