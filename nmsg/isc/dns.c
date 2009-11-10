/* dns nmsg message module */

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

#define MSGTYPE_DNS_ID		7
#define MSGTYPE_DNS_NAME	"dns"

/* Import. */

#include "nmsg_port.h"
#include "nmsg_port_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <wdns.h>

#include "dns.pb-c.c"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_PRINTER(dns_rrname_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_rrtype_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_rrclass_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_rdata_print);

/* Data. */

struct nmsg_msgmod_plugin_field dns_fields[] = {
	{	.type = nmsg_msgmod_ft_bytes,
		.name = "rrname",
		.print = dns_rrname_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrtype",
		.print = dns_rrtype_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrclass",
		.print = dns_rrclass_print
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "rrttl",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rdata",
		.print = dns_rdata_print
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	.msgver = NMSG_MSGMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = { MSGTYPE_DNS_ID, MSGTYPE_DNS_NAME },

	.pbdescr = &nmsg__isc__dns__descriptor,
	.fields = dns_fields
};

/* Private. */

static nmsg_res dns_rrname_print(ProtobufCMessage *m __attribute__((unused)),
				 struct nmsg_msgmod_field *field __attribute__((unused)),
				 void *ptr,
				 struct nmsg_strbuf *sb,
				 const char *endline)
{
	ProtobufCBinaryData *rrname = ptr;
	char name[WDNS_MAXLEN_NAME];
	nmsg_res res = nmsg_res_success;

	if (rrname->len <= WDNS_MAXLEN_NAME) {
		wdns_domain_to_str(rrname->data, name);
		res = nmsg_strbuf_append(sb, "rrname: %s%s", name, endline);
	}
	return (res);
}

static nmsg_res dns_rrtype_print(ProtobufCMessage *m __attribute__((unused)),
				 struct nmsg_msgmod_field *field __attribute__((unused)),
				 void *ptr,
				 struct nmsg_strbuf *sb,
				 const char *endline)
{
	uint32_t *rrtype = ptr;
	const char *s;
	nmsg_res res = nmsg_res_success;

	s = wdns_rrtype_to_str(*rrtype);
	res = nmsg_strbuf_append(sb, "rrtype: %s (%u)%s",
				 s ? s : "<UNKNOWN>",
				 *rrtype, endline);
	return (res);
}

static nmsg_res dns_rrclass_print(ProtobufCMessage *m __attribute__((unused)),
				  struct nmsg_msgmod_field *field __attribute__((unused)),
				  void *ptr,
				  struct nmsg_strbuf *sb,
				  const char *endline)
{
	uint32_t *rrclass = ptr;
	const char *s;
	nmsg_res res = nmsg_res_success;

	s = wdns_rrclass_to_str(*rrclass);
	res = nmsg_strbuf_append(sb, "rrclass: %s (%u)%s",
				 s ? s : "<UNKNOWN>",
				 *rrclass, endline);
	return (res);
}

static nmsg_res dns_rdata_print(ProtobufCMessage *m,
				struct nmsg_msgmod_field *field __attribute__((unused)),
				void *ptr,
				struct nmsg_strbuf *sb,
				const char *endline)
{
	Nmsg__Isc__Dns *dns = (Nmsg__Isc__Dns *) m;
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	wdns_msg_status status;
	char *buf = NULL;
	size_t bufsz;

	if (dns->has_rrtype == false || dns->has_rrclass == false)
		return (nmsg_res_failure);

	status = wdns_rdata_to_str(rdata->data, rdata->len, dns->rrtype,
				   dns->rrclass, NULL, &bufsz);
	if (status != wdns_msg_success)
		goto parse_error;

	buf = malloc(bufsz);
	if (buf == NULL)
		return (nmsg_res_memfail);

	status = wdns_rdata_to_str(rdata->data, rdata->len, dns->rrtype,
				   dns->rrclass, buf, NULL);
	if (status != wdns_msg_success)
		goto parse_error;

	res = nmsg_strbuf_append(sb, "rdata: %s%s", buf, endline);
	free(buf);
	return (nmsg_res_success);

parse_error:
	free(buf);
	nmsg_strbuf_append(sb, "rdata: ### PARSE ERROR #%u ###\n", status);
	return (nmsg_res_parse_error);
}

#if 0
static nmsg_res
dns_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Dns *dns;
	char *buf = NULL;
	char name[WDNS_MAXLEN_NAME];
	nmsg_res res;
	size_t bufsz;
	size_t i;
	struct nmsg_strbuf sbuf;
	wdns_msg_status status;

	memset(&sbuf, 0, sizeof(sbuf));

	/* unpack wire format dns to in-memory struct */
	dns = nmsg__isc__dns__unpack(NULL, np->payload.len, np->payload.data);
	if (dns == NULL)
		return (nmsg_res_memfail);

	/* convert to presentation format */
	if (dns->rrname.len > WDNS_MAXLEN_NAME)
		goto err;

	if (dns->has_rrname) {
		wdns_domain_to_str(dns->rrname.data, name);
		res = nmsg_strbuf_append(&sbuf, "rrname: %s%s", name, el);
		if (res != nmsg_res_success)
			goto err;
	}

	if (dns->has_rrclass) {
		const char *s;

		s = wdns_rrclass_to_str(dns->rrclass);
		res = nmsg_strbuf_append(&sbuf, "rrclass: %s (%u)%s",
					 s ? s : "<UNKNOWN>",
					 dns->rrclass, el);
		if (res != nmsg_res_success)
			goto err;
	}

	if (dns->has_rrtype) {
		const char *s;

		s = wdns_rrtype_to_str(dns->rrtype);
		res = nmsg_strbuf_append(&sbuf, "rrtype: %s (%u)%s",
					 s ? s : "<UNKNOWN>",
					 dns->rrtype, el);
		if (res != nmsg_res_success)
			goto err;
	}

	if (dns->has_rrttl) {
		res = nmsg_strbuf_append(&sbuf, "rrttl: %u%s",
					 dns->rrttl, el);
		if (res != nmsg_res_success)
			goto err;
	}

	for (i = 0; i < dns->n_rdata; i++) {
		res = nmsg_strbuf_append(&sbuf, "rdata: ");
		if (res != nmsg_res_success)
			goto err;

		status = wdns_rdata_to_str(dns->rdata[i].data,
					   dns->rdata[i].len,
					   dns->rrtype, dns->rrclass,
					   NULL, &bufsz);
		if (status == wdns_msg_success) {
			buf = realloc(buf, bufsz);
			if (buf == NULL)
				goto err;

			wdns_rdata_to_str(dns->rdata[i].data,
					  dns->rdata[i].len,
					  dns->rrtype, dns->rrclass,
					  buf, NULL);
			res = nmsg_strbuf_append(&sbuf, "%s\n", buf);
			if (res != nmsg_res_success)
				goto err;
		} else {
			res = nmsg_strbuf_append(&sbuf, "### PARSE ERROR #%u ###\n", status);
			if (res != nmsg_res_success)
				goto err;
		}
	}

	free(buf);

	/* export presentation formatted ncap to caller */
	*pres = sbuf.data;

err:
	/* free unneeded in-memory ncap representation */
	nmsg__isc__dns__free_unpacked(dns, NULL);

	return (nmsg_res_success);
}
#endif

/*! \file nmsg/isc/dns.c
 * \brief ISC "dns" message type.
 *
 * This message type is meant to carry DNS resource records or resource
 * record sets.
 *
 * <b>dns message fields.</b>

<table>

<tr>
<td><b> Name </b></td>
<td><b> Type </b></td>
<td><b> Required </b></td>
<td><b> Repeated </b></td>
<td><b> Description </b></td>
</tr>

<tr>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>

<tr>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>

</table>
*/
