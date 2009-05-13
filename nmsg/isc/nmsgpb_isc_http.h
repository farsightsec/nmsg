#ifndef PBNMSG_ISC_HTTP_H
#define PBNMSG_ISC_HTTP_H

#include "http.pb-c.h"

#define MSGTYPE_HTTP_ID		4
#define MSGTYPE_HTTP_NAME	"http"

/*! \file nmsg/isc/nmsgpb_isc_http.h
 * \brief ISC "http" message type.
 *
 * This message type is meant to carry information about HTTP requests.
 *
 * See nmsg/isc/http.pb-c.h for the C structure definitions used when
 * manipulating HTTP payloads directly.
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

#endif /* PBNMSG_ISC_HTTP_H */
