#ifndef PBNMSG_ISC_LOGLINE_H
#define PBNMSG_ISC_LOGLINE_H

#include "logline.pb-c.h"

#define MSGTYPE_LOGLINE_ID	6
#define MSGTYPE_LOGLINE_NAME	"logline"

/*! \file nmsg/isc/nmsgpb_isc_logline.h
 * \brief ISC "logline" message type.
 *
 * This message type is meant to be carry generic free-form log lines.
 *
 * See nmsg/isc/logline.pb-c.h for the C structure definitions used when
 * manipulating logline payloads directly.
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

#endif /* PBNMSG_ISC_LOGLINE_H */
