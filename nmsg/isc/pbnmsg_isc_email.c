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
#include <nmsg/pbmod.h>

#include "email.pb-c.c"

/* Data. */

#define MSGTYPE_EMAIL_ID	2
#define MSGTYPE_EMAIL_NAME	"email"

#define descrs nmsg__isc__email__field_descriptors
struct nmsg_pbmod_field email_fields[] = {
	{ nmsg_pbmod_ft_enum,		&descrs[6] }, /* type */
	{ nmsg_pbmod_ft_mlstring,	&descrs[0] }, /* headers */
	{ nmsg_pbmod_ft_ip,		&descrs[1] }, /* srcip */
	{ nmsg_pbmod_ft_string,		&descrs[2] }, /* srchost */
	{ nmsg_pbmod_ft_string,		&descrs[3] }, /* helo */
	{ nmsg_pbmod_ft_string,		&descrs[4] }, /* from */
	{ nmsg_pbmod_ft_string,		&descrs[5] }, /* rcpt */
	{ nmsg_pbmod_ft_string,		&descrs[7] }, /* bodyurl */
	{ 0, NULL }
};

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.descr = &nmsg__isc__email__descriptor,
	.fields = email_fields,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_EMAIL_ID, MSGTYPE_EMAIL_NAME },
		NMSG_IDNAME_END
	}
};
