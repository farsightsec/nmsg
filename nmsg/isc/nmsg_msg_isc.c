/* nmsg_msg_isc.c - ISC nmsg_msg modules */

/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#include <nmsg.h>
#include <nmsg/msgmod_plugin.h>

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_email
#include "email.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_http
#include "http.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_ipconn
#include "ipconn.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_linkpair
#include "linkpair.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_logline
#include "logline.c"
#undef nmsg_msgmod_ctx

#if 0
#define nmsg_pbmod_ctx nmsg_pbmod_ctx_ncap
#include "nmsgpb_isc_ncap.c"
#undef nmsg_pbmod_ctx
#endif

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_dns
#include "dns.c"
#undef nmsg_msgmod_ctx

/* Export. */

#if 0
struct nmsg_pbmod *nmsg_pbmod_ctx_array[] = {
	&nmsg_pbmod_ctx_email,
	&nmsg_pbmod_ctx_http,
	&nmsg_pbmod_ctx_ipconn,
	&nmsg_pbmod_ctx_linkpair,
	&nmsg_pbmod_ctx_logline,
	&nmsg_pbmod_ctx_ncap,
	&nmsg_pbmod_ctx_dns,
	NULL
};
#endif

struct nmsg_msgmod_plugin *nmsg_msgmod_ctx_array[] = {
	&nmsg_msgmod_ctx_email,
	&nmsg_msgmod_ctx_http,
	&nmsg_msgmod_ctx_ipconn,
	&nmsg_msgmod_ctx_linkpair,
	&nmsg_msgmod_ctx_logline,
	&nmsg_msgmod_ctx_dns,
	NULL
};
