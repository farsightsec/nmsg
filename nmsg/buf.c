/*
 * Copyright (c) 2008, 2012 by Farsight Security, Inc.
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

/* Internal functions. */

struct nmsg_buf *
_nmsg_buf_new(size_t sz) {
	struct nmsg_buf *buf;

	buf = calloc(1, sizeof(*buf));
	if (buf == NULL)
		return (NULL);
	buf->data = calloc(1, sz);
	if (buf->data == NULL) {
		free(buf);
		return (NULL);
	}
	return (buf);
}

ssize_t
_nmsg_buf_used(struct nmsg_buf *buf) {
	assert(buf->pos >= buf->data);
	return (buf->pos - buf->data);
}

ssize_t
_nmsg_buf_avail(struct nmsg_buf *buf) {
	assert(buf->pos <= buf->end);
	return (buf->end - buf->pos);
}

void
_nmsg_buf_destroy(struct nmsg_buf **buf) {
	if (*buf != NULL) {
		if (_nmsg_global_autoclose == true)
			close((*buf)->fd);
		if ((*buf)->data != NULL)
			free((*buf)->data);
		free(*buf);
		*buf = NULL;
	}
}

void
_nmsg_buf_reset(struct nmsg_buf *buf) {
	buf->end = buf->pos = buf->data;
}
