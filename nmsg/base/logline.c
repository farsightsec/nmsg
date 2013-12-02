/* generic log line nmsg message module */

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

#include "logline.pb-c.h"

/* Data. */

struct nmsg_msgmod_field logline_fields[] = {
	{ .type = nmsg_msgmod_ft_string,	.name = "category"	},
	{ .type = nmsg_msgmod_ft_string,	.name = "message"	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_BASE,
	.msgtype	= { NMSG_VENDOR_BASE_LOGLINE_ID, NMSG_VENDOR_BASE_LOGLINE_NAME },

	.pbdescr	= &nmsg__base__log_line__descriptor,
	.fields		= logline_fields
};

/*! \file nmsg/base/logline.c
 * \brief base "logline" message type.
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
