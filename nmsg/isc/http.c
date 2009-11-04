/* http nmsg message module */

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

#define MSGTYPE_HTTP_ID		4
#define MSGTYPE_HTTP_NAME	"http"

/* Import. */

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

/*! \file nmsg/isc/http.c
 * \brief ISC "http" message type.
 *
 * This message type is meant to carry information about HTTP requests.
 *
 * <b>HTTP message fields.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Type </b></td>
<td><b> Required </b></td>
<td><b> Repeated </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> type </td>
<td> enum HttpType </td>
<td> yes </td>
<td> no </td>
<td> Type of HTTP connection. </td>
</tr>

<tr>
<td> srcip </td>
<td> IP address </td>
<td> no </td>
<td> no </td>
<td> Client IP address </td>
</tr>

<tr>
<td> srchost </td>
<td> string </td>
<td> no </td>
<td> no </td>
<td> Client hostname, if known </td>
</tr>

<tr>
<td> srcport </td>
<td> uint16 </td>
<td> no </td>
<td> no </td>
<td> Client TCP port </td>
</tr>

<tr>
<td> dstip </td>
<td> IP address </td>
<td> no </td>
<td> no </td>
<td> Server IP address </td>
</tr>

<tr>
<td> dstport </td>
<td> uint16 </td>
<td> no </td>
<td> no </td>
<td> Server TCP port </td>
</tr>

<tr>
<td> request </td>
<td> multi-line string </td>
<td> no </td>
<td> no </td>
<td> HTTP request and headers </td>
</tr>

</table>

 * <b>enum HttpType values.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Value </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> unknown </td>
<td> 0 </td>
<td></td>
</tr>

<tr>
<td> sinkhole </td>
<td> 1 </td>
<td> HTTP server is a sinkhole </td>
</tr>

</table>
 */
