/* ipconn nmsg message module */

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

#include "ipconn.pb-c.c"

/* Data. */

struct nmsg_msgmod_field ipconn_fields[] = {
	{ .type = nmsg_msgmod_ft_uint16,	.name = "proto"		},
	{ .type = nmsg_msgmod_ft_ip,		.name = "srcip"		},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "srcport"	},
	{ .type = nmsg_msgmod_ft_ip,		.name = "dstip"		},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "dstport"	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_ISC,
	.msgtype	= { NMSG_VENDOR_ISC_IPCONN_ID, NMSG_VENDOR_ISC_IPCONN_NAME },

	.pbdescr	= &nmsg__isc__ipconn__descriptor,
	.fields		= ipconn_fields
};

/*! \file nmsg/isc/ipconn.c
 * \brief ISC "ipconn" message type.
 *
 * This message type is meant to carry stateless information about IP
 * connections.
 *
 * <b>ipconn message fields.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Type </b></td>
<td><b> Required </b></td>
<td><b> Repeated </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> proto </td>
<td> uint16 </td>
<td> no </td>
<td> no </td>
<td> IP protocol </td>
</tr>

<tr>
<td> srcip </td>
<td> IP address </td>
<td> no </td>
<td> no </td>
<td> Source IP address </td>
</tr>

<tr>
<td> srcport </td>
<td> uint16 </td>
<td> no </td>
<td> no </td>
<td> Source port </td>
</tr>

<tr>
<td> dstip </td>
<td> IP address </td>
<td> no </td>
<td> no </td>
<td> Destination IP address </td>
</tr>

<tr>
<td> dstport </td>
<td> uint16 </td>
<td> no </td>
<td> no </td>
<td> Destination port </td>
</tr>

</table>
 */
