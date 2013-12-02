/* http nmsg message module */

/*
 * Copyright (c) 2009 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

#include "http.pb-c.h"

/* Data. */

struct nmsg_msgmod_field http_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{ .type = nmsg_msgmod_ft_ip,		.name = "srcip"		},
	{ .type = nmsg_msgmod_ft_string,	.name = "srchost"	},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "srcport"	},
	{ .type = nmsg_msgmod_ft_ip,		.name = "dstip"		},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "dstport"	},
	{ .type = nmsg_msgmod_ft_mlstring,	.name = "request"	},

	{ .type = nmsg_msgmod_ft_string,	.name = "p0f_genre"	},
	{ .type = nmsg_msgmod_ft_string,	.name = "p0f_detail"	},
	{ .type = nmsg_msgmod_ft_int16,		.name = "p0f_dist"	},
	{ .type = nmsg_msgmod_ft_string,	.name = "p0f_link"	},
	{ .type = nmsg_msgmod_ft_string,	.name = "p0f_tos"	},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "p0f_fw"	},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "p0f_nat"	},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "p0f_real"	},
	{ .type = nmsg_msgmod_ft_int16,		.name = "p0f_score"	},
	{ .type = nmsg_msgmod_ft_uint16,	.name = "p0f_mflags"	},
	{ .type = nmsg_msgmod_ft_int32,		.name = "p0f_uptime"	},

	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_BASE,
	.msgtype	= { NMSG_VENDOR_BASE_HTTP_ID, NMSG_VENDOR_BASE_HTTP_NAME },

	.pbdescr	= &nmsg__base__http__descriptor,
	.fields		= http_fields
};

/*! \file nmsg/base/http.c
 * \brief base "http" message type.
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
