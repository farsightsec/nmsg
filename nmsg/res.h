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

#ifndef NMSG_RES_H
#define NMSG_RES_H

typedef enum {
	nmsg_res_success,
	nmsg_res_failure,
	nmsg_res_eof,
	nmsg_res_memfail,
	nmsg_res_magic_mismatch,
	nmsg_res_version_mismatch,
	nmsg_res_module_mismatch,
	nmsg_res_msgsize_toolarge,
	nmsg_res_short_send,
	nmsg_res_wrong_buftype,
	nmsg_res_pbuf_ready,
	nmsg_res_pbuf_written,
	nmsg_res_notimpl,
	nmsg_res_unknown_pbmod,
	nmsg_res_no_payload,
	nmsg_res_stop
} nmsg_res;

#endif
