/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#ifndef NMSG_STRBUF_H
#define NMSG_STRBUF_H

#include <stdarg.h>
#include <stddef.h>

#include <nmsg/res.h>

struct nmsg_strbuf {
	char	*pos, *data;
	size_t	bufsz;
};

nmsg_res nmsg_strbuf_append(struct nmsg_strbuf *sb, const char *fmt, ...);
nmsg_res nmsg_strbuf_reset(struct nmsg_strbuf *sb);
size_t nmsg_strbuf_len(struct nmsg_strbuf *sb);
void nmsg_strbuf_free(struct nmsg_strbuf **sb);

#endif /* NMSG_STRBUF_H */
