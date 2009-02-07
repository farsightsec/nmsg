/* pbnmsg_isc_http.c - http protobuf nmsg module */

/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include "nmsg_port.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/asprintf.h>
#include <nmsg/pbmod.h>

#include "http.pb-c.h"

/* Data. */

#define descrs		nmsg__isc__http__field_descriptors
extern const ProtobufCFieldDescriptor descrs[];
struct nmsg_pbmod_field http_fields[] = {
	{ nmsg_pbmod_ft_enum,			&descrs[0] }, /* type */
	{ nmsg_pbmod_ft_ip,			&descrs[1] }, /* srcip */
	{ nmsg_pbmod_ft_string,			&descrs[2] }, /* srchost */
	{ nmsg_pbmod_ft_uint16,			&descrs[3] }, /* srcport */
	{ nmsg_pbmod_ft_ip,			&descrs[4] }, /* dstip */
	{ nmsg_pbmod_ft_uint16,			&descrs[5] }, /* dstport */
	{ nmsg_pbmod_ft_multiline_string,	&descrs[6] }, /* request */
	{ nmsg_pbmod_ft_multiline_string,	&descrs[7] }, /* p0f */
	{ 0, NULL }
};

/* Exported via module context. */

static nmsg_res http_pbuf_to_pres(Nmsg__NmsgPayload *, char **pres,
				  const char *endline);

/* Macros. */

#define MSGTYPE_HTTP_ID		4
#define MSGTYPE_HTTP_NAME	"http"

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.pbuf2pres = &http_pbuf_to_pres,
	.descr = &nmsg__isc__http__descriptor,
	.fields = http_fields,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_HTTP_ID, MSGTYPE_HTTP_NAME },
		NMSG_IDNAME_END
	}
};

/* Exported via module context. */

static nmsg_res
http_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Http *http;
	char srcip[INET6_ADDRSTRLEN], dstip[INET6_ADDRSTRLEN];
	char *srcport = NULL, *dstport = NULL;

	if (np->has_payload == 0)
		return (nmsg_res_failure);
	http = nmsg__isc__http__unpack(NULL, np->payload.len,
				       np->payload.data);

	if (http->has_srcport)
		nmsg_asprintf(&srcport, "srcport: %hu%s",
			      (uint16_t) http->srcport,
			      el);
	if (http->has_dstport)
		nmsg_asprintf(&dstport, "dstport: %hu%s",
			      (uint16_t) http->dstport,
			      el);

	if (http->has_srcip == true) {
		const char *p = NULL;
		if (http->srcip.len == 4) {
			p = inet_ntop(AF_INET, http->srcip.data,
				      srcip, sizeof(srcip));
		} else if (http->srcip.len == 16) {
			p = inet_ntop(AF_INET6, http->srcip.data,
				      srcip, sizeof(srcip));
		}
		if (p == NULL)
			http->has_srcip = false;
	}
	if (http->has_dstip == true) {
		const char *p = NULL;
		if (http->dstip.len == 4) {
			p = inet_ntop(AF_INET, http->dstip.data,
				      dstip, sizeof(dstip));
		} else if (http->dstip.len == 16) {
			p = inet_ntop(AF_INET6, http->dstip.data,
				      dstip, sizeof(dstip));
		}
		if (p == NULL)
			http->has_dstip = false;
	}

	nmsg_asprintf(pres,
		      "type: %s%s"
		      "%s%s%s"		/* srchost */
		      "%s%s%s"		/* srcip */
		      "%s"		/* srcport */
		      "%s%s%s"		/* dstip */
		      "%s"		/* dstport */
		      "%s%s%s%s%s"	/* request */
		      "%s%s%s%s%s"	/* p0f results */
		      "\n"
		      ,
		      /* http_type_to_str(http->type), el, */
		      "DUNNO", el,

		      http->has_srchost	? "srchost: " : "",
		      http->has_srchost	? (char *) http->srchost.data : "",
		      http->has_srchost	? el : "",

		      http->has_srcip	? "srcip: " : "",
		      http->has_srcip	? srcip : "",
		      http->has_srcip	? el : "",

		      srcport != NULL	? srcport : "",

		      http->has_dstip	? "dstip: " : "",
		      http->has_dstip	? dstip : "",
		      http->has_dstip	? el : "",

		      dstport != NULL	? dstport : "",

		      http->has_request	? "request:" : "",
		      http->has_request	? el : "",
		      http->has_request	? (char *) http->request.data : "",
		      http->has_request	? "." : "",
		      http->has_request	? el : "",

		      http->has_p0f	? "p0f:" : "",
		      http->has_p0f	? el : "",
		      http->has_p0f	? (char *) http->p0f.data : "",
		      http->has_p0f	? "." : "",
		      http->has_p0f	? el : ""
	);
	nmsg__isc__http__free_unpacked(http, NULL);
	free(srcport);
	free(dstport);
	return (nmsg_res_success);
}
