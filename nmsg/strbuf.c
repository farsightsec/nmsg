/*
 * Copyright (c) 2023-2024 DomainTools LLC
 * Copyright (c) 2009, 2012-2013, 2016 by Farsight Security, Inc.
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

/* Export. */

struct nmsg_strbuf *
_nmsg_strbuf_init(struct nmsg_strbuf_storage *sbs) {
	sbs->fixed[0] = 0;
	sbs->sb.pos = sbs->sb.data = sbs->fixed;
	sbs->sb.bufsz = sizeof(sbs->fixed);
	return &sbs->sb;
}

struct nmsg_strbuf *
nmsg_strbuf_init(void) {
	struct nmsg_strbuf_storage *sbs;

	sbs = my_calloc(1, sizeof(*sbs));
	return _nmsg_strbuf_init(sbs);
}

#define _nmsg_strbuf_avail(sb)	(sb->bufsz - (sb->pos - sb->data))

static void
_nmsg_strbuf_free(struct nmsg_strbuf_storage *sbs) {
	if (sbs->sb.data != sbs->fixed)
		my_free(sbs->sb.data);
	sbs->sb.pos = sbs->sb.data = sbs->fixed;
	sbs->sb.bufsz = sizeof(sbs->fixed);
}

void
_nmsg_strbuf_destroy(struct nmsg_strbuf_storage *sbs) {
	_nmsg_strbuf_free(sbs);
}

void
nmsg_strbuf_destroy(struct nmsg_strbuf **sb) {
	struct nmsg_strbuf_storage **sbs = (struct nmsg_strbuf_storage **) sb;
	_nmsg_strbuf_destroy(*sbs);
	my_free(*sbs);
}

/* NOTE: This function actually always returns nmsg_res_success. */
nmsg_res
_nmsg_strbuf_expand(struct nmsg_strbuf *sb, size_t len) {
	struct nmsg_strbuf_storage *sbs = (struct nmsg_strbuf_storage *) sb;
	ssize_t needed = len;

	/* determine how many bytes of buffer space are available */
	ssize_t avail = _nmsg_strbuf_avail(sb);
	assert(avail >= 0);

	/* increase buffer size if necessary */
	if (needed > avail) {
		size_t offset = sb->pos - sb->data;
		ssize_t new_bufsz = 2 * sb->bufsz;
		void *ptr;

		while (new_bufsz - (ssize_t) sb->bufsz < needed) {
			new_bufsz *= 2;
		}

		assert(sb->bufsz > 0);

		/* Copy from fixed buffer. */
		if (sb->data == sbs->fixed) {
			ptr = my_malloc(new_bufsz);
			memcpy(ptr, sb->data, offset);
		} else {
			ptr = my_realloc(sb->data, new_bufsz);
		}

		sb->data = ptr;
		sb->pos = sb->data + offset;
		sb->bufsz = new_bufsz;
	}

	return (nmsg_res_success);
}

/* NOTE: This function actually always returns nmsg_res_success. */
nmsg_res
nmsg_strbuf_append_str(struct nmsg_strbuf *sb, const char *str, size_t len) {
	if (len + 1 > _nmsg_strbuf_avail(sb)) {
		nmsg_res result = _nmsg_strbuf_expand(sb, len + 1);
		if (result != nmsg_res_success) {
			return result;
		}
	}

	memcpy(sb->pos, str, len);
	sb->pos += len;
	*sb->pos = '\0';

	return (nmsg_res_success);
}

/* Like nmsg_strbuf_append_str() but escape all problematic JSON characters. */
nmsg_res
nmsg_strbuf_append_str_json(struct nmsg_strbuf *sb, const char *str, size_t len) {
	nmsg_res res;
	const char *scan, *scan_last, *scan_end;

	if (len == 0)
		len = strlen(str);

	scan = scan_last = str;
	scan_end = str + len;

	while (scan < scan_end) {
		char esc = 0;

		switch (*(const unsigned char*) scan) {
			case '\b':
				esc = 'b';
				break;
			case '\f':
				esc = 'f';
				break;
			case '\n':
				esc = 'n';
				break;
			case '\r':
				esc = 'r';
				break;
			case '\t':
				esc = 't';
				break;
			case '"':
				esc = '"';
				break;
			case '\\':
				esc = '\\';
				break;
		}

		if (esc > 0 || *(const unsigned char*) scan <= 0x1f) {

			if (scan > scan_last) {
				res = nmsg_strbuf_append_str(sb, scan_last, (scan - scan_last));

				if (res != nmsg_res_success)
					return res;
			}

			if (esc > 0) {
				char escbuf[2] = { '\\', esc };

				res = nmsg_strbuf_append_str(sb, escbuf, 2);
			} else {
				char hexbuf[8];

				snprintf(hexbuf, sizeof(hexbuf), "\\u00%.2x", *(const unsigned char*) scan);
				res = nmsg_strbuf_append_str(sb, hexbuf, 6);
			}

			if (res != nmsg_res_success)
				return res;

			scan_last = scan + 1;
		}

		scan++;
	}

	return (nmsg_strbuf_append_str(sb, scan_last, (scan_end - scan_last)));
}

char *_nmsg_strbuf_detach(struct nmsg_strbuf *sb) {
	struct nmsg_strbuf_storage *sbs = (struct nmsg_strbuf_storage *) sb;
	char *ptr;

	ptr = (sb->data == sbs->fixed) ? strdup(sbs->fixed) : sb->data;
	sb->pos = sb->data = sbs->fixed;
	sb->bufsz = sizeof(sbs->fixed);

	return ptr;
}

nmsg_res
nmsg_strbuf_append(struct nmsg_strbuf *sb, const char *fmt, ...) {
	ssize_t needed, avail;
	int status;
	nmsg_res result;
	va_list args;

	/* calculate available size */
	avail = _nmsg_strbuf_avail(sb);
	assert(avail >= 0);

	/* Try to print into the buffer or determine needed size */
	va_start(args, fmt);
	needed = vsnprintf(sb->pos, avail, fmt, args);
	va_end(args);
	if (needed < 0) {
		_nmsg_strbuf_free((struct nmsg_strbuf_storage *) sb);
		return (nmsg_res_failure);
	} else if (needed < avail) {
		sb->pos += needed;
		return (nmsg_res_success);
	}

	/* Current buffer size is not enough, allocate additional space */
	result = _nmsg_strbuf_expand(sb, needed + 1);
	if (result != nmsg_res_success) {
		return result;
	}

	/* print to the end of the strbuf */
	va_start(args, fmt);
	status = vsnprintf(sb->pos, needed + 1, fmt, args);
	va_end(args);
	if (status < 0) {
		_nmsg_strbuf_free((struct nmsg_strbuf_storage *) sb);
		return (nmsg_res_failure);
	}

	sb->pos += status;
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
	_nmsg_strbuf_free((struct nmsg_strbuf_storage *) sb);
	return (nmsg_res_success);
}
