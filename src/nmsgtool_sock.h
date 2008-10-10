#ifndef NMSGTOOL_SOCK_H
#define NMSGTOOL_SOCK_H

#include "config.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include "nmsgtool.h"

#ifdef HAVE_SA_LEN
#define NMSGTOOL_SA_LEN(sa) ((sa).sa_len)
#else
#define NMSGTOOL_SA_LEN(sa) ((sa).sa_family == AF_INET ? \
			     sizeof(struct sockaddr_in) :\
			     (sa).sa_family == AF_INET6 ? \
			     sizeof(struct sockaddr_in6) : 0)
#endif

union nmsgtool_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	s4;
	struct sockaddr_in6	s6;
}; 

typedef union nmsgtool_sockaddr nmsgtool_sockaddr;

extern int getsock(nmsgtool_sockaddr *su, const char *addr, unsigned *rate, unsigned *freq);
extern void socksink_init(nmsgtool_ctx *ctx, const char *ss);
extern void socksink_destroy(nmsgtool_ctx *ctx);

#endif
