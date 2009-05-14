#ifndef PBNMSG_ISC_LINKPAIR_H
#define PBNMSG_ISC_LINKPAIR_H

#include "linkpair.pb-c.h"

#define MSGTYPE_LINKPAIR_ID	3
#define MSGTYPE_LINKPAIR_NAME	"linkpair"

/*! \file nmsg/isc/nmsgpb_isc_linkpair.h
 * \brief ISC "linkpair" message type.
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

#endif /* PBNMSG_ISC_LINKPAIR_H */
