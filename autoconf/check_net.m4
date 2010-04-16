AC_CHECK_MEMBER([struct sockaddr.sa_len],
    AC_DEFINE([HAVE_SA_LEN], [1], [Define to 1 if struct sockaddr has an sa_len member.]),
    [],
    [[
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
    ]]
)

AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in_systm.h netinet/in.h dnl
    stddef.h sys/ioctl.h sys/param.h sys/types.h sys/socket.h])
AC_CHECK_HEADERS([net/if.h], [], [],
    [[
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
    ]]
)

AC_CHECK_HEADERS([net/ethernet.h net/ethertypes.h net/if_ether.h dnl
    netinet/if_ether.h netinet/ip.h netinet/ip6.h netinet/tcp.h netinet/udp.h],
    [], [],
    [[
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif
    ]]
)

AC_CHECK_TYPES([struct ether_header, struct ip, struct ip6_hdr, struct tcphdr,
    struct udphdr], [], AC_MSG_ERROR([struct definition missing.]),
    [[
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP6_H
# include <netinet/ip6.h>
#endif

#ifdef HAVE_NETINET_UDP_H
# include <netinet/udp.h>
#endif

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
# include <net/ethernet.h>
#endif

#ifdef HAVE_NET_ETHERTYPES_H
# include <net/ethertypes.h>
#endif

#ifdef HAVE_NET_IF_ETHER_H
# include <net/if_ether.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif
    ]]
)
