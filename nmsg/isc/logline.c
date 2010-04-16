/* generic log line nmsg message module */

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

#include "logline.pb-c.c"

/* Data. */

struct nmsg_msgmod_field logline_fields[] = {
	{ .type = nmsg_msgmod_ft_string,	.name = "category"	},
	{ .type = nmsg_msgmod_ft_string,	.name = "message"	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	.msgver		= NMSG_MSGMOD_VERSION,
	.vendor		= NMSG_VENDOR_ISC,
	.msgtype	= { NMSG_VENDOR_ISC_LOGLINE_ID, NMSG_VENDOR_ISC_LOGLINE_NAME },

	.pbdescr	= &nmsg__isc__log_line__descriptor,
	.fields		= logline_fields
};

/*! \file nmsg/isc/logline.c
 * \brief ISC "logline" message type.
 *
 * This message type is meant to be carry generic free-form log lines.
 *
 * <b>logline message fields.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Type </b></td>
<td><b> Required </b></td>
<td><b> Repeated </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> category </td>
<td> string </td>
<td> no </td>
<td> no </td>
<td> Free-form string containing the category of the log message. </td>
</tr>

<tr>
<td> message </td>
<td> string </td>
<td> no </td>
<td> no </td>
<td> Free-form string containing the log message itself. </td>
</tr>

</table>
*/
