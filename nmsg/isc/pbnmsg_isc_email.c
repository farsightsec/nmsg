/* pbnmsg_isc_email.c - email protobuf nmsg module */

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

#include "pbnmsg_isc_email.h"
#include "email.pb-c.c"

/* Data. */

struct nmsg_pbmod_field email_fields[] = {
	{ nmsg_pbmod_ft_enum,		"type",		NULL },
	{ nmsg_pbmod_ft_mlstring,	"headers",	NULL },
	{ nmsg_pbmod_ft_ip,		"srcip",	NULL },
	{ nmsg_pbmod_ft_string,		"srchost",	NULL },
	{ nmsg_pbmod_ft_string,		"helo",		NULL },
	{ nmsg_pbmod_ft_string,		"from",		NULL },
	{ nmsg_pbmod_ft_string,		"rcpt",		NULL },
	{ nmsg_pbmod_ft_string,		"bodyurl",	NULL },
	{ 0, NULL, NULL }
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver		= NMSG_PBMOD_VERSION,
	.pbdescr	= &nmsg__isc__email__descriptor,
	.pbfields	= nmsg__isc__email__field_descriptors,
	.fields		= email_fields,
	.vendor		= NMSG_VENDOR_ISC,
	.msgtype	= {
		{ MSGTYPE_EMAIL_ID, MSGTYPE_EMAIL_NAME },
		NMSG_IDNAME_END
	}
};
