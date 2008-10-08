/* pbnmsg_isc_emailhdr.c - emailhdr protobuf nmsg module */

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

#include <stdio.h>

#include <nmsg.h>

/* Forward. */
static nmsg_res emailhdr_init(void);
static nmsg_res emailhdr_fini(void);

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { 1, "emailhdr" },
	.init = &emailhdr_init,
	.fini = &emailhdr_fini
};

/* Exported via module context. */

static nmsg_res
emailhdr_init(void) {
	printf("starting pbnmsg_isc_emailhdr\n");
	return nmsg_res_success;
}

static nmsg_res
emailhdr_fini(void) {
	return nmsg_res_success;
}
