/* dns nmsg message module */

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

#include <wdns.h>

#include "dns.pb-c.h"

/* Exported via module context. */

static NMSG_MSGMOD_FIELD_PRINTER(dns_name_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_type_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_class_print);
static NMSG_MSGMOD_FIELD_PRINTER(dns_rdata_print);

/* Data. */

struct nmsg_msgmod_field dns_fields[] = {
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "qname",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qclass",
		.print = dns_class_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qtype",
		.print = dns_type_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "section",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rrname",
		.print = dns_name_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrclass",
		.print = dns_class_print
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrtype",
		.print = dns_type_print
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "rrttl",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rdata",
		.flags = NMSG_MSGMOD_FIELD_REPEATED,
		.print = dns_rdata_print
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor = NMSG_VENDOR_BASE,
	.msgtype = { NMSG_VENDOR_BASE_DNS_ID, NMSG_VENDOR_BASE_DNS_NAME },

	.pbdescr = &nmsg__base__dns__descriptor,
	.fields = dns_fields
};

/* Private. */

static nmsg_res
dns_name_print(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       void *ptr,
	       struct nmsg_strbuf *sb,
	       const char *endline)
{
	ProtobufCBinaryData *rrname = ptr;
	char name[WDNS_PRESLEN_NAME];
	nmsg_res res = nmsg_res_success;

	if (rrname->data != NULL &&
	    rrname->len > 0 &&
	    rrname->len <= WDNS_MAXLEN_NAME)
	{
		wdns_domain_to_str(rrname->data, rrname->len, name);
		res = nmsg_strbuf_append(sb, "%s: %s%s", field->name,
					 name, endline);
	}
	return (res);
}

static nmsg_res
dns_type_print(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       void *ptr,
	       struct nmsg_strbuf *sb,
	       const char *endline)
{
	uint16_t *rrtype = ptr;
	const char *s;
	nmsg_res res = nmsg_res_success;

	s = wdns_rrtype_to_str(*rrtype);
	res = nmsg_strbuf_append(sb, "%s: %s (%hu)%s",
				 field->name,
				 s ? s : "<UNKNOWN>",
				 *rrtype, endline);
	return (res);
}

static nmsg_res
dns_class_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	uint16_t *rrclass = ptr;
	const char *s;
	nmsg_res res = nmsg_res_success;

	s = wdns_rrclass_to_str(*rrclass);
	res = nmsg_strbuf_append(sb, "%s: %s (%hu)%s",
				 field->name,
				 s ? s : "<UNKNOWN>",
				 *rrclass, endline);
	return (res);
}

static nmsg_res
dns_rdata_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field __attribute__((unused)),
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	Nmsg__Base__Dns *dns = (Nmsg__Base__Dns *) nmsg_message_get_payload(msg);
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	char *buf;

	if (dns == NULL)
		return (nmsg_res_failure);

	if (dns->has_rrtype == false || dns->has_rrclass == false)
		return (nmsg_res_failure);

	buf = wdns_rdata_to_str(rdata->data, rdata->len, dns->rrtype, dns->rrclass);
	if (buf == NULL)
		goto parse_error;

	res = nmsg_strbuf_append(sb, "rdata: %s%s", buf, endline);
	free(buf);
	return (res);

parse_error:
	free(buf);
	nmsg_strbuf_append(sb, "rdata: ### PARSE ERROR ###\n");
	return (nmsg_res_parse_error);
}

/*! \file nmsg/base/dns.c
 * \brief base "dns" message type.
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
