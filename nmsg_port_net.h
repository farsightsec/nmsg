#ifndef NMSG_PORT_NET_H
#define NMSG_PORT_NET_H

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

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef __APPLE__
# include <sys/ioctl.h>
# define BIOCIMMEDIATE _IOW('B',112, u_int)
#endif

#ifndef ETHER_HDR_LEN
# define ETHER_HDR_LEN 14
#endif

#ifndef IP_OFFMASK
# define IP_OFFMASK 0x1fff
#endif

#ifndef ETHERTYPE_IP
# define ETHERTYPE_IP 0x0800
#endif

#ifndef ETHERTYPE_VLAN
# define ETHERTYPE_VLAN 0x8100
#endif

#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6 0x86dd
#endif

#ifndef IPV6_VERSION
# define IPV6_VERSION 0x60
#endif

#ifndef IPV6_VERSION_MASK
# define IPV6_VERSION_MASK 0xf0
#endif

#endif /* NMSG_PORT_NET_H */
