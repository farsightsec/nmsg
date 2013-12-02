/* link pair nmsg message module */

/*
 * Copyright (c) 2008, 2009 by Farsight Security, Inc.
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

#include "linkpair.pb-c.h"

/* Data. */

struct nmsg_msgmod_field linkpair_fields[] = {
	{
		.type = nmsg_msgmod_ft_enum,
		.name = "type",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "src",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "dst",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{ .type = nmsg_msgmod_ft_mlstring,	.name = "headers"	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_BASE,
	.msgtype	= { NMSG_VENDOR_BASE_LINKPAIR_ID, NMSG_VENDOR_BASE_LINKPAIR_NAME },

	.pbdescr	= &nmsg__base__linkpair__descriptor,
	.fields		= linkpair_fields
};

/*! \file nmsg/base/linkpair.c
 * \brief base "linkpair" message type.
 *
 * This message type is meant to carry information about links between webpages.
 *
 * <b> linkpair message fields.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Type </b></td>
<td><b> Required </b></td>
<td><b> Repeated </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> type </b></td>
<td> enum Linktype </td>
<td> yes </td>
<td> no </td>
<td> Type of link pair. </td>
</tr>

<tr>
<td> src </td>
<td> string </td>
<td> yes </td>
<td> no </td>
<td> URI of source page. </td>
</tr>

<tr>
<td> dst </td>
<td> string </td>
<td> yes </td>
<td> no </td>
<td> URI of destination page. </td>
</tr>

<tr>
<td> headers </td>
<td> multi-line string </td>
<td> no </td>
<td> no </td>
<td> HTTP response headers of destination page. </td>
</tr>

</table>

 * <b>enum Linktype values.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Value </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> anchor </td>
<td> 0 </td>
<td> link created by an &lt;A HREF&gt; tag </td>
</tr>

<tr>
<td> redirect </td>
<td> 1 </td>
<td> link created by an HTTP redirect </td>
</tr>

</table>
 */
