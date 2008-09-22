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

static nmsg_res nmsg_ensure_buffer(nmsg_source ns, ssize_t bytes);
static nmsg_res nmsg_fill_buffer(nmsg_source ns);
static nmsg_res nmsg_read_header(nmsg_source ns);
static nmsg_source nmsg_new(void);
static ssize_t nmsg_bytes_avail(nmsg_source ns);

/* Export. */

nmsg_source
nmsg_open_file(const char *fname) {
	int fd;
	nmsg_source ns;

	fd = open(fname, O_RDONLY);
	if (fd == -1)
		return (NULL);
	ns = nmsg_new();
	if (ns == NULL)
		return (NULL);
	ns->fd = fd;
	if (nmsg_read_header(ns) != nmsg_res_success) {
		nmsg_source_destroy(&ns);
		return (NULL);
	}

	return (ns);
}

nmsg_source
nmsg_open_fd(int fd) {
	nmsg_source ns;
	
	ns = nmsg_new();
	if (ns == NULL)
		return (NULL);
	ns->fd = fd;
	if (nmsg_read_header(ns) != nmsg_res_success) {
		nmsg_source_destroy(&ns);
		return (NULL);
	}

	return (ns);
}

void
nmsg_source_destroy(nmsg_source *ns) {
	close((*ns)->fd);
	free((*ns)->buf);
	free(*ns);
	*ns = NULL;
}

nmsg_res
nmsg_read_pbuf(nmsg_source ns, Nmsg__Nmsg **nmsg) {
	nmsg_res res;
	ssize_t bytes_avail;
	uint16_t msgsize;

	res = nmsg_ensure_buffer(ns, sizeof msgsize);
	if (res != nmsg_res_success)
		return (nmsg_res_short_read);
	msgsize = ntohs(*(uint16_t *) ns->buf_pos);
	ns->buf_pos += 2;
	if (msgsize > nmsg_msgsize)
		return (nmsg_res_msgsize_toolarge);
	bytes_avail = nmsg_bytes_avail(ns);

	if (msgsize > bytes_avail) {
		ssize_t bytes_needed;

		bytes_needed = msgsize - bytes_avail;
		while (msgsize > bytes_avail) {
			ssize_t bytes_read;

			bytes_needed = msgsize - bytes_avail;
			bytes_read = read(ns->fd, ns->buf_end, bytes_needed);
			if (bytes_read < 0)
				return (false);
			if (bytes_read == 0)
				return (nmsg_res_eof);
			ns->buf_end += bytes_read;
			bytes_avail = nmsg_bytes_avail(ns);
		}
	}
	*nmsg = nmsg__nmsg__unpack(NULL, msgsize, ns->buf_pos);
	ns->buf_pos += msgsize;

	return (nmsg_res_success);
}

nmsg_res
nmsg_loop(nmsg_source ns, int cnt, nmsg_handler cb, void *user) {
	nmsg_res res;
	Nmsg__Nmsg *nmsg;

	if (cnt < 0) {
		for(;;) {
			res = nmsg_read_pbuf(ns, &nmsg);
			if (res == nmsg_res_success) {
				cb(nmsg, user);
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			} else {
				nmsg__nmsg__free_unpacked(nmsg, NULL);
				return (res);
			}
		}
	} else {
		int i;
		for (i = 0; i < cnt; i++) {
			res = nmsg_read_pbuf(ns, &nmsg);
			if (res == nmsg_res_success) {
				cb(nmsg, user);
				nmsg__nmsg__free_unpacked(nmsg, NULL);
			} else {
				nmsg__nmsg__free_unpacked(nmsg, NULL);
				return (res);
			}
		}
	}

	return (nmsg_res_success);
}

/* Private. */

nmsg_res
nmsg_read_header(nmsg_source ns) {
	char magic[] = nmsg_magic;
	nmsg_res res;
	uint16_t vers;

	res = nmsg_ensure_buffer(ns, nmsg_hdrsize);
	if (res != nmsg_res_success)
		return (res);
	if (memcmp(ns->buf_pos, magic, sizeof(magic)) != 0)
		return (nmsg_res_magic_mismatch);
	ns->buf_pos += sizeof(magic);
	vers = ntohs(*(uint16_t *) ns->buf_pos);
	ns->buf_pos += sizeof(vers);
	if (vers != nmsg_version)
		return (nmsg_res_version_mismatch);
	return (nmsg_res_success);
}

static ssize_t
nmsg_bytes_avail(nmsg_source ns) {
	if (ns->buf_pos > ns->buf_end)
		return (-1);
	return (ns->buf_end - ns->buf_pos);
}

static nmsg_res
nmsg_fill_buffer(nmsg_source ns) {
	ssize_t bytes_read;
	
	bytes_read = read(ns->fd, ns->buf, nmsg_msgsize);
	if (bytes_read < 0)
		return (nmsg_res_failure);
	if (bytes_read == 0)
		return (nmsg_res_eof);
	ns->buf_pos = ns->buf;
	ns->buf_end = ns->buf + bytes_read;
	return (nmsg_res_success);
}

static nmsg_res
nmsg_ensure_buffer(nmsg_source ns, ssize_t bytes) {
	nmsg_res res;

	if (nmsg_bytes_avail(ns) < bytes) {
		res = nmsg_fill_buffer(ns);
		if (res == nmsg_res_success && nmsg_bytes_avail(ns) < bytes)
			return (nmsg_res_failure);
		else
			return (res);
	}
	return (nmsg_res_success);
}

static nmsg_source
nmsg_new(void) {
	nmsg_source ns;

	ns = calloc(1, sizeof(*ns));
	if (ns == NULL)
		return (NULL);
	ns->buf = malloc(nmsg_bufsize);
	if (ns->buf == NULL) {
		free(ns);
		return (NULL);
	}
	return (ns);
}
