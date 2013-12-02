/* email nmsg message module */

/*
 * Copyright (c) 2008, 2009, 2013 by Farsight Security, Inc.
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

#include "email.pb-c.h"

/* Data. */

struct nmsg_msgmod_field email_fields[] = {
	{ .type = nmsg_msgmod_ft_enum,		.name = "type"		},
	{ .type = nmsg_msgmod_ft_mlstring,	.name = "headers"	},
	{ .type = nmsg_msgmod_ft_ip,		.name = "srcip"		},
	{ .type = nmsg_msgmod_ft_string,	.name = "srchost"	},
	{ .type = nmsg_msgmod_ft_string,	.name = "helo"		},
	{ .type = nmsg_msgmod_ft_string,	.name = "from"		},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "rcpt",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	{
		.type = nmsg_msgmod_ft_string,
		.name = "bodyurl",
		.flags = NMSG_MSGMOD_FIELD_REPEATED
	},
	{ .type = nmsg_msgmod_ft_mlstring,	.name = "body"		},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_BASE,
	.msgtype	= { NMSG_VENDOR_BASE_EMAIL_ID, NMSG_VENDOR_BASE_EMAIL_NAME },

	.pbdescr	= &nmsg__base__email__descriptor,
	.fields		= email_fields
};

/*! \file nmsg/base/email.c
 * \brief base "email" message type.
 *
 * This message type is meant to carry information about the envelope,
 * headers, and body of an email message delivered over SMTP.
 *
 * <b>Email message fields.</b>

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
<td> enum EmailType </td>
<td> no </td>
<td> no </td>
<td> Type of email </td>
</tr>

<tr>
<td> headers </td>
<td> multi-line string </td>
<td> no </td>
<td> no </td>
<td> Email headers; may be redacted </td>
</tr>

<tr>
<td> srcip </td>
<td> IP address </td>
<td> no </td>
<td> no </td>
<td> Remote client IP </td>
</tr>

<tr>
<td> srchost </td>
<td> string </td>
<td> no </td>
<td> no </td>
<td> Remote client hostname, if known </td>
</tr>

<tr>
<td> helo </td>
<td> string </td>
<td> no </td>
<td> no </td>
<td> HELO/EHLO SMTP parameter </td>
</tr>

<tr>
<td> from </td>
<td> string </td>
<td> no </td>
<td> no </td>
<td> MAIL FROM SMTP parameter (brackets stripped) </td>
</tr>

<tr>
<td> rcpt </td>
<td> string </td>
<td> no </td>
<td> yes </td>
<td> RCPT TO SMTP parameters(s) (brackets stripped) </td>
</tr>

<tr>
<td> bodyurl </td>
<td> string </td>
<td> no </td>
<td> yes </td>
<td> URL(s) found in decoded body </td>
</tr>

</table>

 * <b>enum EmailType values.</b>

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
<td> spamtrap </td>
<td> 1 </td>
<td> Email sent to a spamtrap </td>
</tr>

<tr>
<td> rej_network </td>
<td> 2 </td>
<td> Rejected by network or SMTP (pre-DATA) checks, including IP blacklists. </td>
</tr>

<tr>
<td> rej_content </td>
<td> 3 </td>
<td> Rejected by content filter, including domain blacklists.
</tr>

<tr>
<td> rej_user </td>
<td> 4 </td>
<td> Classified by user as spam.
</tr>

</table>
 */
