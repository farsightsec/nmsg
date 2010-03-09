#include "config.h"

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ustr.h>

#include "../buf.h"
#include "../constants.h"
#include "../msg.h"
#include "record_descr.h"

#if DEBUG
# define VERBOSE(format, ...) do { printf("%s(%d): " format, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)
#else
# define VERBOSE(format, ...)
#endif

#define WDNS_ERROR(val) do { \
	VERBOSE(#val "\n"); \
	return (val); \
} while(0)

#define WDNS_FLAGS_QR(msg)             ((((msg).flags) >> 15) & 0x01)
#define WDNS_FLAGS_OPCODE(msg)         ((((msg).flags) >> 11) & 0x0f)
#define WDNS_FLAGS_AA(msg)             ((((msg).flags) >> 10) & 0x01)
#define WDNS_FLAGS_TC(msg)             ((((msg).flags) >> 9) & 0x01)
#define WDNS_FLAGS_RD(msg)             ((((msg).flags) >> 8) & 0x01)
#define WDNS_FLAGS_RA(msg)             ((((msg).flags) >> 7) & 0x01)
#define WDNS_FLAGS_Z(msg)              ((((msg).flags) >> 6) & 0x01)
#define WDNS_FLAGS_AD(msg)             ((((msg).flags) >> 5) & 0x01)
#define WDNS_FLAGS_CD(msg)             ((((msg).flags) >> 4) & 0x01)
#define WDNS_FLAGS_RCODE(msg)          ((msg).rcode)

wdns_msg_status
_wdns_insert_rr_rrset_array(wdns_rrset_array_t *a, wdns_rr_t *rr, unsigned sec);

wdns_msg_status
_wdns_parse_edns(wdns_message_t *m, wdns_rr_t *rr);

wdns_msg_status
_wdns_parse_rdata(const uint8_t *p, const uint8_t *eop, const uint8_t *ordata,
		  uint16_t rrtype, uint16_t rrclass, uint16_t rdlen,
		  size_t *alloc_bytes, uint8_t *dst);

wdns_msg_status
_wdns_parse_header(const uint8_t *p, size_t len, uint16_t *id, uint16_t *flags,
		   uint16_t *qdcount, uint16_t *ancount, uint16_t *nscount, uint16_t *arcount);

wdns_msg_status
_wdns_parse_message_rr(unsigned sec, const uint8_t *p, const uint8_t *eop, const uint8_t *data,
		       size_t *rrsz, wdns_rr_t *rr);

void
_wdns_rr_to_ustr(Ustr **, wdns_rr_t *rr, unsigned sec);

void
_wdns_rrset_to_ustr(Ustr **, wdns_rrset_t *rrset, unsigned sec);

void
_wdns_rrset_array_to_ustr(Ustr **, wdns_rrset_array_t *a, unsigned sec);
