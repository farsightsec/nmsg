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

/* Import. */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <nmsg/asprintf.h>
#include <nmsg/strbuf.h>
#include <nmsg/res.h>

#define DEFAULT_STRBUF_ALLOC_SZ		1024

nmsg_res
nmsg_strbuf_append(struct nmsg_strbuf *sb, const char *fmt, ...) {
	ssize_t avail, needed;
	int status;
	va_list args, args_copy;

	/* allocate a data buffer if necessary */
	if (sb->data == NULL) {
		sb->pos = sb->data = malloc(DEFAULT_STRBUF_ALLOC_SZ);
		if (sb->data == NULL)
			return (nmsg_res_memfail);
		sb->bufsz = DEFAULT_STRBUF_ALLOC_SZ;
	}

	/* determine how many bytes are needed */
	va_start(args, fmt);
	va_copy(args_copy, args);
	needed = vsnprintf(NULL, 0, fmt, args_copy);
	va_end(args_copy);
	if (needed < 0) {
		free(sb->data);
		sb->pos = sb->data = NULL;
		sb->bufsz = 0;
		return (nmsg_res_failure);
	}

	/* determine how many bytes of buffer space are available */
	avail = sb->bufsz - (sb->pos - sb->data);
	assert(avail >= 0);

	/* increase buffer size if necessary */
	if (needed > avail) {
		size_t offset;
		ssize_t new_bufsz = 2 * sb->bufsz;
		void *ptr = sb->data;

		offset = sb->pos - sb->data;

		while (new_bufsz - (ssize_t) sb->bufsz < needed)
			new_bufsz *= 2;
		assert(sb->bufsz > 0);
		ptr = realloc(sb->data, new_bufsz);
		if (ptr == NULL) {
			free(sb->data);
			sb->pos = sb->data = NULL;
			sb->bufsz = 0;
			return (nmsg_res_memfail);
		}
		sb->data = ptr;
		sb->pos = sb->data + offset;
		sb->bufsz = new_bufsz;
	}

	/* print to the end of the strbuf */
	status = vsnprintf(sb->pos, needed + 1, fmt, args);
	if (status >= 0)
		sb->pos += status;
	else {
		free(sb->data);
		sb->pos = sb->data = NULL;
		sb->bufsz = 0;
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

size_t
nmsg_strbuf_len(struct nmsg_strbuf *sb) {
	assert(sb->pos >= sb->data);
	assert(sb->pos - sb->data <= (ssize_t) sb->bufsz);
	return (sb->pos - sb->data);
}

nmsg_res
nmsg_strbuf_reset(struct nmsg_strbuf *sb) {
	void *ptr = sb->data;
	
	ptr = realloc(sb->data, DEFAULT_STRBUF_ALLOC_SZ);
	if (ptr == NULL) {
		free(sb->data);
		sb->pos = sb->data = NULL;
		sb->bufsz = 0;
		return (nmsg_res_memfail);
	}
	sb->pos = sb->data = ptr;
	sb->bufsz = DEFAULT_STRBUF_ALLOC_SZ;

	return (nmsg_res_success);
}

void
nmsg_strbuf_free(struct nmsg_strbuf **sb) {
	free((*sb)->data);
	free(*sb);
	*sb = NULL;
}
