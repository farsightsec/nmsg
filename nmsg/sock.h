/*
 * Copyright (c) 2010 by Internet Systems Consortium, Inc. ("ISC")
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

#ifndef NMSG_SOCK_H
#define NMSG_SOCK_H

/*! \file nmsg/sock.h
 * \brief Socket utilities.
 */

#include <nmsg.h>

/**
 * Parse a "socket spec" string.
 *
 * \param[in] sockspec The "socket spec" string.
 * \param[out] af Address family (AF_INET or AF_INET6).
 * \param[out] addr Network address. Dynamically allocated; must be
 *	freed with free().
 * \param[out] port_start Start of network port range.
 * \param[out] port_end End of network port range.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */

nmsg_res
nmsg_sock_parse_sockspec(const char *sockspec, int *af, char **addr,
			 unsigned *port_start, unsigned *port_end);

#endif /* NMSG_SOCK_H */
