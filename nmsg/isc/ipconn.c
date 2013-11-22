/* ipconn nmsg message module */

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

#include "ipconn.pb-c.h"

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
