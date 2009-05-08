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

/*! \file nmsg/dns.h
 * \brief DNS utility functions.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>

#include <nmsg.h>

/**
 * Dump a DNS payload into presentation form.
 *
 * \param [in,out] sb string buffer to append decoded DNS payload to.
 *
 * \param [in] payload DNS payload data.
 *
 * \param [in] paylen DNS payload length.
 *
 * \param [in] el end of line string.
 *
 * \return #nmsg_res_success
 */
nmsg_res
nmsg_dns_dump(nmsg_strbuf_t sb, const u_char *payload, size_t paylen,
	      const char *el);

#endif /* NMSG_DNS_H */
