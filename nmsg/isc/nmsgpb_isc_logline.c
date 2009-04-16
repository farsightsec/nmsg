/* nmsgpb_isc_logline.c - generic log line protobuf nmsg module */

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

#include "nmsgpb_isc_logline.h"
#include "logline.pb-c.c"

/* Data. */

struct nmsg_pbmod_field logline_fields[] = {
	{ .type = nmsg_pbmod_ft_string,	.name = "category"	},
	{ .type = nmsg_pbmod_ft_string,	.name = "message"	},
	NMSG_PBMOD_FIELD_END
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver		= NMSG_PBMOD_VERSION,
	.pbdescr	= &nmsg__isc__log_line__descriptor,
	.pbfields	= nmsg__isc__log_line__field_descriptors,
	.fields		= logline_fields,
	.vendor		= NMSG_VENDOR_ISC,
	.msgtype	= { MSGTYPE_LOGLINE_ID, MSGTYPE_LOGLINE_NAME }
};
