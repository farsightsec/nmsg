/* pbnmsg_isc_http.c - http protobuf nmsg module */

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

#include "pbnmsg_isc_http.h"
#include "http.pb-c.c"

/* Data. */

struct nmsg_pbmod_field http_fields[] = {
	{ nmsg_pbmod_ft_enum,		"type",		NULL },
	{ nmsg_pbmod_ft_ip,		"srcip",	NULL },
	{ nmsg_pbmod_ft_string,		"srchost",	NULL },
	{ nmsg_pbmod_ft_uint16,		"srcport",	NULL },
	{ nmsg_pbmod_ft_ip,		"dstip",	NULL },
	{ nmsg_pbmod_ft_uint16,		"dstport",	NULL },
	{ nmsg_pbmod_ft_mlstring,	"request",	NULL },

	{ nmsg_pbmod_ft_string,		"p0f_genre",	NULL },
	{ nmsg_pbmod_ft_string,		"p0f_detail",	NULL },
	{ nmsg_pbmod_ft_int16,		"p0f_dist",	NULL },
	{ nmsg_pbmod_ft_string,		"p0f_link",	NULL },
	{ nmsg_pbmod_ft_string,		"p0f_tos",	NULL },
	{ nmsg_pbmod_ft_uint16,		"p0f_fw",	NULL },
	{ nmsg_pbmod_ft_uint16,		"p0f_nat",	NULL },
	{ nmsg_pbmod_ft_uint16,		"p0f_real",	NULL },
	{ nmsg_pbmod_ft_int16,		"p0f_score",	NULL },
	{ nmsg_pbmod_ft_uint16,		"p0f_mflags",	NULL },
	{ nmsg_pbmod_ft_int32,		"p0f_uptime",	NULL },

	{ 0, NULL, NULL }
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver		= NMSG_PBMOD_VERSION,
	.pbdescr	= &nmsg__isc__http__descriptor,
	.pbfields	= nmsg__isc__http__field_descriptors,
	.fields		= http_fields,
	.vendor		= NMSG_VENDOR_ISC,
	.msgtype	= { MSGTYPE_HTTP_ID, MSGTYPE_HTTP_NAME }
};
