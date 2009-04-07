/* pbnmsg_isc_ipconn.c - ipconn protobuf nmsg module */

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

#include <nmsg.h>

#include "pbnmsg_isc_ipconn.h"
#include "ipconn.pb-c.c"

/* Data. */

struct nmsg_pbmod_field ipconn_fields[] = {
	{ nmsg_pbmod_ft_uint16,		"proto",	NULL },
	{ nmsg_pbmod_ft_ip,		"srcip",	NULL },
	{ nmsg_pbmod_ft_uint16,		"srcport",	NULL },
	{ nmsg_pbmod_ft_ip,		"dstip",	NULL },
	{ nmsg_pbmod_ft_uint16,		"dstport",	NULL },
	{ 0, NULL, NULL }
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver		= NMSG_PBMOD_VERSION,
	.pbdescr	= &nmsg__isc__ipconn__descriptor,
	.pbfields	= nmsg__isc__ipconn__field_descriptors,
	.fields		= ipconn_fields,
	.vendor		= NMSG_VENDOR_ISC,
	.msgtype	= {
		{ MSGTYPE_IPCONN_ID, MSGTYPE_IPCONN_NAME },
		NMSG_IDNAME_END
	}
};
