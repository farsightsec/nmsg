#ifndef NMSG_PRIVATE_H
#define NMSG_PRIVATE_H

#include <stddef.h>

#define nmsg_msgsize	8192
#define nmsg_bufsize	(2 * nmsg_msgsize)

struct nmsg_input {
	int	fd;
	u_char	*buf_pos;
	u_char	*buf_end;
	u_char	*buf;
};

#endif
