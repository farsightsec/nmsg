/* nmsgpb_isc_http.c - http protobuf nmsg module */

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

#include "nmsgpb_isc_http.h"
#include "http.pb-c.c"

/* Data. */

struct nmsg_pbmod_field http_fields[] = {
	{ .type = nmsg_pbmod_ft_enum,		.name = "type"		},
	{ .type = nmsg_pbmod_ft_ip,		.name = "srcip"		},
	{ .type = nmsg_pbmod_ft_string,		.name = "srchost"	},
	{ .type = nmsg_pbmod_ft_uint16,		.name = "srcport"	},
	{ .type = nmsg_pbmod_ft_ip,		.name = "dstip"		},
	{ .type = nmsg_pbmod_ft_uint16,		.name = "dstport"	},
	{ .type = nmsg_pbmod_ft_mlstring,	.name = "request"	},

	{ .type = nmsg_pbmod_ft_string,		.name = "p0f_genre"	},
	{ .type = nmsg_pbmod_ft_string,		.name = "p0f_detail"	},
	{ .type = nmsg_pbmod_ft_int16,		.name = "p0f_dist"	},
	{ .type = nmsg_pbmod_ft_string,		.name = "p0f_link"	},
	{ .type = nmsg_pbmod_ft_string,		.name = "p0f_tos"	},
	{ .type = nmsg_pbmod_ft_uint16,		.name = "p0f_fw"	},
	{ .type = nmsg_pbmod_ft_uint16,		.name = "p0f_nat"	},
	{ .type = nmsg_pbmod_ft_uint16,		.name = "p0f_real"	},
	{ .type = nmsg_pbmod_ft_int16,		.name = "p0f_score"	},
	{ .type = nmsg_pbmod_ft_uint16,		.name = "p0f_mflags"	},
	{ .type = nmsg_pbmod_ft_int32,		.name = "p0f_uptime"	},

	NMSG_PBMOD_FIELD_END
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver		= NMSG_PBMOD_VERSION,
	.vendor		= NMSG_VENDOR_ISC,
	.msgtype	= { MSGTYPE_HTTP_ID, MSGTYPE_HTTP_NAME },

	.pbdescr	= &nmsg__isc__http__descriptor,
	.pbfields	= nmsg__isc__http__field_descriptors,
	.fields		= http_fields
};
