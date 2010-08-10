#include "config.h"

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#endif

#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
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
#include "b32_encode.h"
#include "b64_encode.h"

wdns_msg_status
_wdns_insert_rr_rrset_array(wdns_rrset_array_t *a, wdns_rr_t *rr, unsigned sec);

wdns_msg_status
_wdns_parse_edns(wdns_message_t *m, wdns_rr_t *rr);

wdns_msg_status
_wdns_parse_rdata(wdns_rr_t *rr, const uint8_t *p, const uint8_t *eop,
		  const uint8_t *rdata, uint16_t rdlen);

wdns_msg_status
_wdns_parse_header(const uint8_t *p, size_t len, uint16_t *id, uint16_t *flags,
		   uint16_t *qdcount, uint16_t *ancount, uint16_t *nscount, uint16_t *arcount);

wdns_msg_status
_wdns_parse_message_rr(unsigned sec, const uint8_t *p, const uint8_t *eop, const uint8_t *data,
		       size_t *rrsz, wdns_rr_t *rr);

void
_wdns_rdata_to_ustr(Ustr **s, const uint8_t *rdata, uint16_t rdlen,
		    uint16_t rrtype, uint16_t rrclass);

void
_wdns_rr_to_ustr(Ustr **, wdns_rr_t *rr, unsigned sec);

void
_wdns_rrset_to_ustr(Ustr **, wdns_rrset_t *rrset, unsigned sec);

void
_wdns_rrset_array_to_ustr(Ustr **, wdns_rrset_array_t *a, unsigned sec);
