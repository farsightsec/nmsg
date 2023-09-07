/* dns nmsg message module */

/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2009, 2015, 2021 by Farsight Security, Inc.
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

static NMSG_MSGMOD_FIELD_FORMATTER(dns_name_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dns_type_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dns_class_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dns_rdata_format);

static NMSG_MSGMOD_FIELD_PARSER(dns_name_parse);
static NMSG_MSGMOD_FIELD_PARSER(dns_type_parse);
static NMSG_MSGMOD_FIELD_PARSER(dns_class_parse);
static NMSG_MSGMOD_FIELD_PARSER(dns_rdata_parse);

/* Data. */

struct nmsg_msgmod_field dns_fields[] = {
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "qname",
		.print = dns_name_print,
		.format = dns_name_format,
		.parse = dns_name_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qclass",
		.print = dns_class_print,
		.format = dns_class_format,
		.parse = dns_class_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "qtype",
		.print = dns_type_print,
		.format = dns_type_format,
		.parse = dns_type_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "section",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rrname",
		.print = dns_name_print,
		.format = dns_name_format,
		.parse = dns_name_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrclass",
		.print = dns_class_print,
		.format = dns_class_format,
		.parse = dns_class_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint16,
		.name = "rrtype",
		.print = dns_type_print,
		.format = dns_type_format,
		.parse = dns_type_parse,
	},
	{
		.type = nmsg_msgmod_ft_uint32,
		.name = "rrttl",
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "rdata",
		.flags = NMSG_MSGMOD_FIELD_REPEATED,
		.print = dns_rdata_print,
		.format = dns_rdata_format,
		.parse = dns_rdata_parse,
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
dns_name_format(nmsg_message_t m,
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
		res = nmsg_strbuf_append_str(sb, name, strlen(name));
	}
	return (res);
}

static nmsg_res
dns_name_parse(nmsg_message_t m,
	       struct nmsg_msgmod_field *field,
	       const char *value,
	       void **ptr,
	       size_t *len,
	       const char *endline)
{
	wdns_res res;
	wdns_name_t *name;

	name = malloc(sizeof(*name));
	if (name == NULL) {
		return (nmsg_res_memfail);
	}

	res = wdns_str_to_name_case(value, name);
	if (res != wdns_res_success) {
		free (name);
		return (nmsg_res_parse_error);
	}

	*ptr = name->data;
	*len = name->len;

	free(name);

	return (nmsg_res_success);
}

static nmsg_res
dns_type_print(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       void *ptr,
	       struct nmsg_strbuf *sb,
	       const char *endline)
{
	uint16_t rrtype;
	const char *s;
	nmsg_res res = nmsg_res_success;

	memcpy(&rrtype, ptr, sizeof(rrtype));
	s = wdns_rrtype_to_str(rrtype);
	res = nmsg_strbuf_append(sb, "%s: %s (%u)%s",
				 field->name,
				 s ? s : "<UNKNOWN>",
				 rrtype, endline);
	return (res);
}

static nmsg_res
dns_type_format(nmsg_message_t m,
	        struct nmsg_msgmod_field *field,
	        void *ptr,
	        struct nmsg_strbuf *sb,
	        const char *endline)
{
	uint16_t rrtype;
	const char *s;
	char buf[sizeof("TYPE65535")];
	nmsg_res res = nmsg_res_success;

	memcpy(&rrtype, ptr, sizeof(rrtype));
	s = wdns_rrtype_to_str(rrtype);
	if (s == NULL) {
		snprintf(buf, sizeof(buf), "TYPE%u", rrtype);
		s = &buf[0];
	}
	res = nmsg_strbuf_append_str(sb, s, strlen(s));
	return (res);
}

static nmsg_res
dns_type_parse(nmsg_message_t msg,
	       struct nmsg_msgmod_field *field,
	       const char *value,
	       void **ptr,
	       size_t *len,
	       const char *endline)
{
	uint16_t *rrtype;

	rrtype = malloc(sizeof(*rrtype));
	if (rrtype == NULL) {
		return (nmsg_res_memfail);
	}

	*rrtype = wdns_str_to_rrtype(value);
	if (*rrtype == 0 && strcasecmp(value, "TYPE0") != 0) {
		free(rrtype);
		return (nmsg_res_parse_error);
	}

	*ptr = rrtype;
	*len = sizeof(*rrtype);

	return (nmsg_res_success);
}

static nmsg_res
dns_class_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field,
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	uint16_t rrclass;
	const char *s;
	nmsg_res res = nmsg_res_success;

	memcpy(&rrclass, ptr, sizeof(rrclass));
	s = wdns_rrclass_to_str(rrclass);
	if (s == NULL) {
		res = nmsg_strbuf_append(sb, "%s: CLASS%hu (%u)%s",
					 field->name, rrclass, rrclass, endline);
	} else {
		res = nmsg_strbuf_append(sb, "%s: %s (%u)%s",
					 field->name, s, rrclass, endline);
	}
	return (res);
}

static nmsg_res
dns_class_format(nmsg_message_t m,
	         struct nmsg_msgmod_field *field,
	         void *ptr,
	         struct nmsg_strbuf *sb,
	         const char *endline)
{
	uint16_t rrclass;
	const char *s;
	nmsg_res res = nmsg_res_success;

	memcpy(&rrclass, ptr, sizeof(rrclass));
	s = wdns_rrclass_to_str(rrclass);
	if (s != NULL) {
		res = nmsg_strbuf_append_str(sb, s, strlen(s));
	} else {
		res = nmsg_strbuf_append(sb, "CLASS%hu", rrclass);
	}
	return (res);
}

static nmsg_res
dns_class_parse(nmsg_message_t m,
	        struct nmsg_msgmod_field *field,
	        const char *value,
	        void **ptr,
	        size_t *len,
	        const char *endline)
{
	uint16_t *rrclass;

	rrclass = malloc(sizeof(*rrclass));
	if (rrclass == NULL) {
		return (nmsg_res_memfail);
	}

	*rrclass = wdns_str_to_rrclass(value);
	if (*rrclass == 0 && strcasecmp(value, "CLASS0") != 0) {
		free(rrclass);
		return (nmsg_res_parse_error);
	}

	*ptr = rrclass;
	*len = sizeof(*rrclass);

	return (nmsg_res_success);
}

static nmsg_res
dns_rdata_print(nmsg_message_t msg,
		struct nmsg_msgmod_field *field __attribute__((unused)),
		void *ptr,
		struct nmsg_strbuf *sb,
		const char *endline)
{
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	char *buf;
	uint32_t *rrtype, *rrclass;
	size_t len;

	res = nmsg_message_get_field(msg, "rrtype", 0, (void **) &rrtype, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	res = nmsg_message_get_field(msg, "rrclass", 0, (void **) &rrclass, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	buf = wdns_rdata_to_str(rdata->data, rdata->len, *rrtype, *rrclass);
	if (buf == NULL)
		return (nmsg_res_memfail);

	res = nmsg_strbuf_append(sb, "rdata: %s%s", buf, endline);
	free(buf);
	return (res);
}

static nmsg_res
dns_rdata_format(nmsg_message_t msg,
	         struct nmsg_msgmod_field *field,
	         void *ptr,
	         struct nmsg_strbuf *sb,
	         const char *endline)
{
	ProtobufCBinaryData *rdata = ptr;
	nmsg_res res;
	char *buf;
	uint32_t *rrtype, *rrclass;
	size_t len;

	res = nmsg_message_get_field(msg, "rrtype", 0, (void **) &rrtype, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	res = nmsg_message_get_field(msg, "rrclass", 0, (void **) &rrclass, &len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	buf = wdns_rdata_to_str(rdata->data, rdata->len, *rrtype, *rrclass);
	if (buf == NULL)
		return (nmsg_res_memfail);

	res = nmsg_strbuf_append_str(sb, buf, strlen(buf));
	free(buf);
	return (res);
}

static nmsg_res
dns_rdata_parse(nmsg_message_t m,
	        struct nmsg_msgmod_field *field,
	        const char *value,
	        void **ptr,
	        size_t *len,
	        const char *endline)
{
	nmsg_res res;
	wdns_res w_res;
	uint32_t *rrtype, *rrclass;
	size_t f_len;

	res = nmsg_message_get_field(m, "rrtype", 0, (void **) &rrtype, &f_len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (f_len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	res = nmsg_message_get_field(m, "rrclass", 0, (void **) &rrclass, &f_len);
	if (res != nmsg_res_success) {
		return (nmsg_res_failure);
	}
	if (f_len != sizeof(uint32_t)) {
		return (nmsg_res_failure);
	}

	w_res = wdns_str_to_rdata(value, *rrtype, *rrclass, (uint8_t **) ptr, len);
	if (w_res == wdns_res_parse_error) {
		return (nmsg_res_parse_error);
	} else if (w_res != wdns_res_success) {
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
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
