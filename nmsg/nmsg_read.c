/* nmsg_read.c - interface for reading nmsg messages */

/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "nmsg_private.h"

/* Forward. */

static nmsg_res nmsg_ensure_buffer(nmsg_input ni, ssize_t bytes);
static nmsg_res nmsg_fill_buffer(nmsg_input ni);
static nmsg_res nmsg_read_header(nmsg_input ni);
static nmsg_input nmsg_new(void);
static ssize_t nmsg_bytes_avail(nmsg_input ni);

/* Export. */

nmsg_input
nmsg_open_file(const char *fname) {
	int fd;
	nmsg_input ni;

	fd = open(fname, O_RDONLY);
	if (fd == -1)
		return (NULL);
	ni = nmsg_new();
	if (ni == NULL)
		return (NULL);
	ni->fd = fd;
	if (nmsg_read_header(ni) != nmsg_res_success) {
		nmsg_input_destroy(&ni);
		return (NULL);
	}

	return (ni);
}

nmsg_input
nmsg_open_fd(int fd) {
	nmsg_input ni;
	
	ni = nmsg_new();
	if (ni == NULL)
		return (NULL);
	ni->fd = fd;
	if (nmsg_read_header(ni) != nmsg_res_success) {
		nmsg_input_destroy(&ni);
		return (NULL);
	}

	return (ni);
}

void
nmsg_input_destroy(nmsg_input *ni) {
	close((*ni)->fd);
	free((*ni)->buf);
	free(*ni);
	*ni = NULL;
}

nmsg_res
nmsg_read_pbuf(nmsg_input ni, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail;
	uint16_t msgsize;

	res = nmsg_ensure_buffer(ni, sizeof msgsize);
	if (res != nmsg_res_success)
		return (nmsg_res_short_read);
	msgsize = ntohs(*(uint16_t *) ni->buf_pos);
	ni->buf_pos += 2;
	if (msgsize > nmsg_msgsize)
		return (nmsg_res_msgsize_toolarge);
	bytes_avail = nmsg_bytes_avail(ni);

	if (msgsize > bytes_avail) {
		ssize_t bytes_needed;

		bytes_needed = msgsize - bytes_avail;
		while (msgsize > bytes_avail) {
			ssize_t bytes_read;

			bytes_needed = msgsize - bytes_avail;
			bytes_read = read(ni->fd, ni->buf_end, bytes_needed);
			if (bytes_read < 0)
				return (false);
			if (bytes_read == 0)
				return (nmsg_res_eof);
			ni->buf_end += bytes_read;
			bytes_avail = nmsg_bytes_avail(ni);
		}
	}
	*nmsg = nmsg__nmsg__unpack(NULL, msgsize, ni->buf_pos);
	ni->buf_pos += msgsize;

	return (nmsg_res_success);
}

nmsg_res
nmsg_loop(nmsg_input ni, int cnt, nmsg_handler cb, void *user) {
	int i;
	unsigned n;
	nmsg_res res;
	Nmsg__Nmsg *nmsg;

	if (cnt < 0) {
		for(;;) {
			res = nmsg_read_pbuf(ni, &nmsg);
			if (res == nmsg_res_success) {
				for (n = 0; n < nmsg->n_payloads; n++)
					cb(nmsg->payloads[n], user);
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			} else {
				return (res);
			}
		}
	} else {
		for (i = 0; i < cnt; i++) {
			res = nmsg_read_pbuf(ni, &nmsg);
			if (res == nmsg_res_success) {
				for (n = 0; n < nmsg->n_payloads; n++)
					cb(nmsg->payloads[n], user);
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			} else {
				return (res);
			}
		}
	}

	return (nmsg_res_success);
}

/* Private. */

nmsg_res
nmsg_read_header(nmsg_input ni) {
	char magic[] = nmsg_magic;
	nmsg_res res;
	uint16_t vers;

	res = nmsg_ensure_buffer(ni, nmsg_hdrsize);
	if (res != nmsg_res_success)
		return (res);
	if (memcmp(ni->buf_pos, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	ni->buf_pos += sizeof(magic);
	vers = ntohs(*(uint16_t *) ni->buf_pos);
	ni->buf_pos += sizeof(vers);
	if (vers != nmsg_version)
		return (nmsg_res_version_mismatch);
	return (nmsg_res_success);
}

static ssize_t
nmsg_bytes_avail(nmsg_input ni) {
	if (ni->buf_pos > ni->buf_end)
		return (-1);
	return (ni->buf_end - ni->buf_pos);
}

static nmsg_res
nmsg_fill_buffer(nmsg_input ni) {
	ssize_t bytes_read;
	
	bytes_read = read(ni->fd, ni->buf, nmsg_msgsize);
	if (bytes_read < 0)
		return (nmsg_res_failure);
	if (bytes_read == 0)
		return (nmsg_res_eof);
	ni->buf_pos = ni->buf;
	ni->buf_end = ni->buf + bytes_read;
	return (nmsg_res_success);
}

static nmsg_res
nmsg_ensure_buffer(nmsg_input ni, ssize_t bytes) {
	nmsg_res res;

	if (nmsg_bytes_avail(ni) < bytes) {
		res = nmsg_fill_buffer(ni);
		if (res == nmsg_res_success && nmsg_bytes_avail(ni) < bytes)
			return (nmsg_res_failure);
		else
			return (res);
	}
	return (nmsg_res_success);
}

static nmsg_input
nmsg_new(void) {
	nmsg_input ni;

	ni = calloc(1, sizeof(*ni));
	if (ni == NULL)
		return (NULL);
	ni->buf = malloc(nmsg_bufsize);
	if (ni->buf == NULL) {
		free(ni);
		return (NULL);
	}
	return (ni);
}
