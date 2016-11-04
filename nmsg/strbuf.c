/*
 * Copyright (c) 2009, 2012 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

#include "private.h"

/* Macros. */

#define DEFAULT_STRBUF_ALLOC_SZ		1024

/* Export. */

struct nmsg_strbuf *
nmsg_strbuf_init(void) {
	struct nmsg_strbuf *sb;

	sb = calloc(1, sizeof(*sb));

	return (sb);
}

void
nmsg_strbuf_destroy(struct nmsg_strbuf **sb) {
	free((*sb)->data);
	free(*sb);
	*sb = NULL;
}

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
	needed = vsnprintf(NULL, 0, fmt, args_copy) + 1;
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
		void *ptr;

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
	void *ptr;

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
