/* pbnmsg_isc_linkpair.c - link pair protobuf nmsg module */

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
#include <nmsg/pbmod.h>

#include "linkpair.pb-c.c"

/* Data. */

#define MSGTYPE_LINKPAIR_ID	3
#define MSGTYPE_LINKPAIR_NAME	"linkpair"

#define descrs nmsg__isc__linkpair__field_descriptors
struct nmsg_pbmod_field linkpair_fields[] = {
	{ nmsg_pbmod_ft_enum,			&descrs[0] }, /* type */
	{ nmsg_pbmod_ft_string,			&descrs[1] }, /* src */
	{ nmsg_pbmod_ft_string,			&descrs[2] }, /* dst */
	{ nmsg_pbmod_ft_multiline_string,	&descrs[4] }, /* headers */
	{ 0, NULL }
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.descr = &nmsg__isc__linkpair__descriptor,
	.fields = linkpair_fields,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_LINKPAIR_ID, MSGTYPE_LINKPAIR_NAME },
		NMSG_IDNAME_END
	}
};
