#ifndef NMSG_PORT_NET_H
#define NMSG_PORT_NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdint.h>

#ifndef ETHER_HDR_LEN
# define ETHER_HDR_LEN 14
#endif

#ifndef ETH_ALEN
# define ETH_ALEN 6
#endif

#ifndef IP_OFFMASK
# define IP_OFFMASK 0x1fff
#endif

#ifndef IP_DF
# define IP_DF 0x4000
#endif

#ifndef IP_MF
# define IP_MF 0x2000
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

#ifndef IP6F_OFF_MASK
# if !defined(WORDS_BIGENDIAN)
#  define IP6F_OFF_MASK 0xf8ff
# else
#  define IP6F_OFF_MASK 0xfff8
# endif
#endif

/* Macros. */

#define load_net16(buf, out) do { \
	uint16_t _my_16; \
	memcpy(&_my_16, buf, sizeof(uint16_t)); \
	_my_16 = ntohs(_my_16); \
	*(out) = _my_16; \
} while (0)

#define load_net32(buf, out) do { \
	uint32_t _my_32; \
	memcpy(&_my_32, buf, sizeof(uint32_t)); \
	_my_32 = ntohl(_my_32); \
	*(out) = _my_32; \
} while (0)

#define store_net16(buf, in) do { \
	uint16_t _my_16 = htons(in); \
	memcpy(buf, &_my_16, sizeof(uint16_t)); \
} while (0)

#define store_net32(buf, in) do { \
	uint32_t _my_32 = htonl(in); \
	memcpy(buf, &_my_32, sizeof(uint32_t)); \
} while (0)

/* Data types. */

struct nmsg_ethhdr {
	uint8_t		ether_dhost[ETH_ALEN];
	uint8_t		ether_shost[ETH_ALEN];
	uint16_t	ether_type;
} __attribute__ ((__packed__));

struct nmsg_iphdr {
#if !defined(WORDS_BIGENDIAN)
	unsigned int	ip_hl:4;
	unsigned int	ip_v:4;
#else
	unsigned int	ip_v:4;
	unsigned int	ip_hl:4;
#endif
	uint8_t		ip_tos;
	uint16_t	ip_len;
	uint16_t	ip_id;
	uint16_t	ip_off;
	uint8_t		ip_ttl;
	uint8_t		ip_p;
	uint16_t	ip_sum;
	uint32_t	ip_src;
	uint32_t	ip_dst;
} __attribute__ ((__packed__));

struct nmsg_tcphdr {
	uint16_t	th_sport;
	uint16_t	th_dport;
	uint32_t	th_seq;
	uint32_t	th_ack;
#if !defined(WORDS_BIGENDIAN)
	uint8_t		th_x2:4;
	uint8_t		th_off:4;
#else
	uint8_t		th_off:4;
	uint8_t		th_x2:4;
#endif
	uint8_t		th_flags;
	uint16_t	th_win;
	uint16_t	th_sum;
	uint16_t	th_urp;
} __attribute__ ((__packed__));

struct nmsg_udphdr {
	uint16_t	uh_sport;
	uint16_t	uh_dport;
	uint16_t	uh_ulen;
	uint16_t	uh_sum;
} __attribute__ ((__packed__));

struct nmsg_icmphdr {
	uint8_t		icmp_type;
	uint8_t		icmp_code;
	uint16_t	icmp_cksum;
} __attribute__ ((__packed__));

#endif /* NMSG_PORT_NET_H */
