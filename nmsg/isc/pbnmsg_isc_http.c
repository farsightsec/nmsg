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
#include <nmsg/pbmod.h>

#include "http.pb-c.c"

/* Data. */

#define MSGTYPE_HTTP_ID		4
#define MSGTYPE_HTTP_NAME	"http"

#define descrs nmsg__isc__http__field_descriptors
struct nmsg_pbmod_field http_fields[] = {
	{ nmsg_pbmod_ft_enum,			&descrs[0] }, /* type */
	{ nmsg_pbmod_ft_ip,			&descrs[1] }, /* srcip */
	{ nmsg_pbmod_ft_string,			&descrs[2] }, /* srchost */
	{ nmsg_pbmod_ft_uint16,			&descrs[3] }, /* srcport */
	{ nmsg_pbmod_ft_ip,			&descrs[4] }, /* dstip */
	{ nmsg_pbmod_ft_uint16,			&descrs[5] }, /* dstport */
	{ nmsg_pbmod_ft_multiline_string,	&descrs[6] }, /* request */
	{ nmsg_pbmod_ft_multiline_string,	&descrs[7] }, /* p0f */
	{ 0, NULL }
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.descr = &nmsg__isc__http__descriptor,
	.fields = http_fields,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_HTTP_ID, MSGTYPE_HTTP_NAME },
		NMSG_IDNAME_END
	}
};
