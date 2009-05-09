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

#include <nmsg.h>

/*! \file nmsg/strbuf.h
 * \brief String buffers
 *
 * Dynamically sized strings that may be appended to or reset.
 */

/** String buffer. */
struct nmsg_strbuf {
	char	*pos;	/*%< end of string */
	char	*data;	/*%< buffer for string data */
	size_t	bufsz;	/*%< size of data allocation */
};

/**
 * Append to a string buffer.
 *
 * \param[in] sb string buffer.
 *
 * \param[in] fmt format string to be passed to vsnprintf.
 *
 * \param[in] ... arguments to vsnprintf.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 * \return #nmsg_res_failure
 */
nmsg_res nmsg_strbuf_append(struct nmsg_strbuf *sb, const char *fmt, ...);

/**
 * Reset a string buffer.
 *
 * Resets the size of the internal buffer to the default size, but does not
 * clear the contents of the buffer.
 *
 * \param[in] sb string buffer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 */
nmsg_res nmsg_strbuf_reset(struct nmsg_strbuf *sb);

/**
 * Find the length of the used portion of the string buffer.
 *
 * \param[in] sb string buffer.
 *
 * \return Number of bytes consumed by the string.
 */
size_t nmsg_strbuf_len(struct nmsg_strbuf *sb);

/**
 * Destroy all resources associated with a string buffer.
 *
 * \param[in] sb pointer to string buffer.
 */
void nmsg_strbuf_free(struct nmsg_strbuf **sb);

#endif /* NMSG_STRBUF_H */
