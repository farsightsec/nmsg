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

#ifndef NMSG_OUTPUT_H
#define NMSG_OUTPUT_H

#include <sys/types.h>

#include <nmsg.h>
#include <nmsg/nmsg.pb-c.h>

nmsg_buf
nmsg_output_open_file(int fd, size_t bufsz);

nmsg_buf
nmsg_output_open_sock(int fd, size_t bufsz);

nmsg_pres
nmsg_output_open_pres(int fd);

nmsg_res
nmsg_output_append(nmsg_buf, Nmsg__NmsgPayload *);

nmsg_res
nmsg_output_close(nmsg_buf *);

void
nmsg_output_set_allocator(nmsg_buf, ProtobufCAllocator *);

void
nmsg_output_set_rate(nmsg_buf, unsigned, unsigned);

#endif
