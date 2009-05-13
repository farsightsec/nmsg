#ifndef PBNMSG_ISC_EMAIL_H
#define PBNMSG_ISC_EMAIL_H

#include "email.pb-c.h"

#define MSGTYPE_EMAIL_ID	2
#define MSGTYPE_EMAIL_NAME	"email"

/*! \file nmsg/isc/nmsgpb_isc_email.h
 * \brief ISC "email" message type.
 *
 * This message type is meant to carry information about the envelope,
 * headers, and body of an email message delivered over SMTP.
 *
 * See nmsg/isc/email.pb-c.h for the C structure definitions used when
 * manipulating email payloads directly.
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

#endif /* PBNMSG_ISC_EMAIL_H */
