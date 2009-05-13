#ifndef PBNMSG_ISC_IPCONN_H
#define PBNMSG_ISC_IPCONN_H

#include "ipconn.pb-c.h"

#define MSGTYPE_IPCONN_ID	5
#define MSGTYPE_IPCONN_NAME	"ipconn"

/*! \file nmsg/isc/nmsgpb_isc_ipconn.h
 * \brief ISC "ipconn" message type.
 * 
 * This message type is meant to carry stateless information about IP
 * connections.
 *
 * See nmsg/isc/ipconn.pb-c.h for the C structure definitions used when
 * manipulating ipconn payloads directly.
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

#endif /* PBNMSG_ISC_IPCONN_H */
