#ifndef MY_FAST_INET_NTOP_H
#define MY_FAST_INET_NTOP_H

#include <sys/socket.h>

const char *fast_inet4_ntop(const void *restrict src, char *restrict dst, socklen_t size);
const char *fast_inet6_ntop(const void *restrict src, char *restrict dst, socklen_t size);
const char *fast_inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size);

#endif /* MY_FAST_INET_NTOP_H */
