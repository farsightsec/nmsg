/*
 * Copyright (c) 2007, 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef NMSG_DUMP_DNS_H
#define NMSG_DUMP_DNS_H

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>

#include <nmsg.h>

nmsg_res
nmsg_dns_dump(nmsg_strbuf_t, const u_char *payload, size_t paylen, const char *el);

nmsg_res
nmsg_dns_dump_sect(nmsg_strbuf_t, ns_msg *msg, ns_sect sect, const char *el);

nmsg_res
nmsg_dns_dump_rr(nmsg_strbuf_t, ns_msg *msg, ns_rr *rr, ns_sect sect);

nmsg_res
nmsg_dns_dump_rrname(nmsg_strbuf_t, ns_rr *rr);

nmsg_res
nmsg_dns_dump_rd(nmsg_strbuf_t, const u_char *msg, const u_char *eom,
		 unsigned type, const u_char *rdata, unsigned rdlen);

const char *
nmsg_dns_dump_rcode(unsigned rcode);

const char *
nmsg_dns_dump_class(unsigned class);

const char *
nmsg_dns_dump_type(unsigned type);

#endif /* NMSG_DUMP_DNS_H */
