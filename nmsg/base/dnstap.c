/* dnstap nmsg message module */

/*
 * Copyright (c) 2016 by Farsight Security, Inc.
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

#include "dnstap.pb-c.h"

/* Exported via module context. */

static nmsg_res
dnstap_message_load(nmsg_message_t m, void **msg_clos);

static nmsg_res
dnstap_message_fini(nmsg_message_t m, void *msg_clos);

static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_message_type);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_socket_family);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_socket_protocol);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_address);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_port);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_time_sec);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_time_nsec);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_query_zone);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_dns);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_id);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_qname);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_qclass);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_qtype);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_rcode);

static NMSG_MSGMOD_FIELD_FORMATTER(dnstap_message_type_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dnstap_socket_family_format);
static NMSG_MSGMOD_FIELD_FORMATTER(dnstap_socket_protocol_format);

static NMSG_MSGMOD_FIELD_PRINTER(dnstap_message_type_print);
static NMSG_MSGMOD_FIELD_PRINTER(dnstap_socket_family_print);
static NMSG_MSGMOD_FIELD_PRINTER(dnstap_socket_protocol_print);

/* Data. */

struct nmsg_msgmod_field dnstap_fields[] = {
	{ .type = nmsg_msgmod_ft_bytes, 	.name="identity" },
	{ .type = nmsg_msgmod_ft_bytes,		.name="version" },
	{ .type = nmsg_msgmod_ft_bytes,		.name="extra" },
	{
	  .type = nmsg_msgmod_ft_enum,
	  .name="type",
	  .flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "message_type",
	  .get = dnstap_get_message_type,
	  .format = dnstap_message_type_format,
	  .print = dnstap_message_type_print
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "socket_family",
	  .get = dnstap_get_socket_family,
	  .format = dnstap_socket_family_format,
	  .print = dnstap_socket_family_print
        },
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "socket_protocol",
	  .get = dnstap_get_socket_protocol,
	  .format = dnstap_socket_protocol_format,
	  .print = dnstap_socket_protocol_print
        },
	{
	  .type = nmsg_msgmod_ft_ip,
	  .name = "query_address",
	  .get = dnstap_get_address
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "query_port",
	  .get = dnstap_get_port
	},
	{
	  .type = nmsg_msgmod_ft_uint64,
	  .name = "query_time_sec",
	  .get = dnstap_get_time_sec
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "query_time_nsec",
	  .get = dnstap_get_time_nsec
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "query_message",
	  .get = dnstap_get_dns,
	  .print = dnsqr_message_print
	},
	{
	  .type = nmsg_msgmod_ft_ip,
	  .name = "response_address",
	  .get = dnstap_get_address
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "response_port",
	  .get = dnstap_get_port
	},
	{
	  .type = nmsg_msgmod_ft_uint64,
	  .name = "response_time_sec",
	  .get = dnstap_get_time_sec
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "response_time_nsec",
	  .get = dnstap_get_time_nsec
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "query_zone",
	  .get = dnstap_get_query_zone,
	  .print = dns_name_print,
	  .format = dns_name_format
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "response_message",
	  .get = dnstap_get_dns,
	  .print = dnsqr_message_print
	},
	{
	  .type = nmsg_msgmod_ft_uint16,
	  .name = "id",
	  .get = dnstap_get_id
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "qname",
	  .get = dnstap_get_qname,
	  .print = dns_name_print,
	  .format = dns_name_format
	},
	{
	  .type = nmsg_msgmod_ft_uint16,
	  .name = "qclass",
	  .get = dnstap_get_qclass,
	  .print = dns_class_print,
	  .format = dns_class_format
	},
	{
	  .type = nmsg_msgmod_ft_uint16,
	  .name = "qtype",
	  .get = dnstap_get_qtype,
	  .print = dns_type_print,
	  .format = dns_type_format
	},
	{
	  .type = nmsg_msgmod_ft_uint16,
	  .name = "rcode",
	  .get = dnstap_get_rcode,
	  .print = dnsqr_rcode_print,
	  .format = dnsqr_rcode_format
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor = NMSG_VENDOR_BASE,
	.msgtype = { NMSG_VENDOR_BASE_DNSTAP_ID, NMSG_VENDOR_BASE_DNSTAP_NAME },
	.msg_load = dnstap_message_load,
	.msg_fini = dnstap_message_fini,
	.pbdescr = &dnstap__dnstap__descriptor,
	.fields = dnstap_fields
};

/* Private */

struct dnstap_priv {
	bool has_id;
	bool has_qclass;
	bool has_qtype;
	bool has_rcode;
	bool has_qname;
	uint16_t id;
	uint16_t qclass;
	uint16_t qtype;
	uint16_t rcode;
	wdns_name_t qname;
};

/* Functions */

static nmsg_res
dnstap_message_load(nmsg_message_t m, void **msg_clos) {
	struct dnstap_priv *priv;
	const uint8_t *p, *op;
	uint16_t flags, qdcount;
	size_t len;
	Dnstap__Dnstap *dnstap;
	Dnstap__Message *msg;

	dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(m);
	if (dnstap == NULL || dnstap->message == NULL) {
		return (nmsg_res_success);
	}

	msg = dnstap->message;

	if (msg->has_query_message) {
		p = msg->query_message.data;
		len = msg->query_message.len;
	} else if (msg->has_response_message) {
		p = msg->response_message.data;
		len = msg->response_message.len;
	} else {
		return (nmsg_res_success);
	}

	if (len < 12) {
		return (nmsg_res_success);
	}

	*msg_clos = priv = calloc(1, sizeof(struct dnstap_priv));
	load_net16(p, &priv->id);
	load_net16(p+2, &flags);
	load_net16(p+4, &qdcount);

	priv->rcode = flags & 0xf;
	priv->has_id = priv->has_rcode = true;

	p += 12;
	len -= 12;

	if (qdcount == 1 && len > 0) {
		op = p;
		priv->qname.len = wdns_skip_name(&p, p + len);
		priv->has_qname = true;

		priv->qname.data = my_malloc(priv->qname.len);
		memcpy(priv->qname.data, op, priv->qname.len);

		len -= priv->qname.len;

		if (len < 2) {
			return (nmsg_res_success);
		}

		priv->qtype = ntohs(*(uint16_t *)p);
		priv->has_qtype = true;
		p += 2;
		len -= 2;

		if (len < 2) {
			return (nmsg_res_success);
		}

		priv->qclass = ntohs(*(uint16_t *)p);
		priv->has_qclass = true;
	}

	return (nmsg_res_success);
}

static nmsg_res
dnstap_message_fini(nmsg_message_t m, void *msg_clos) {
	struct dnstap_priv *priv = (struct dnstap_priv *)msg_clos;

	if (priv != NULL && priv->qname.data != NULL)
		free(priv->qname.data);
	free(priv);
	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_message_type(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	*data = (void *)&dnstap->message->type;
	if (len)
		*len = sizeof(dnstap->message->type);

	return (nmsg_res_success);
}

static nmsg_res
dnstap_message_type_format(nmsg_message_t msg,
			struct nmsg_msgmod_field *field,
			void *ptr,
			struct nmsg_strbuf *sb,
			const char *endline)
{
	const ProtobufCEnumValue *eval;
	int val = *((int *)ptr);
	eval = protobuf_c_enum_descriptor_get_value(&dnstap__message__type__descriptor, val);
	if (eval == NULL) {
		return (nmsg_res_failure);
	}
	nmsg_strbuf_append_str(sb, eval->name, strlen(eval->name));
	return (nmsg_res_success);
}

static nmsg_res
dnstap_message_type_print(nmsg_message_t msg,
			struct nmsg_msgmod_field *field,
			void *ptr,
			struct nmsg_strbuf *sb,
			const char *endline)
{
	const ProtobufCEnumValue *eval;
	int val = *((int *)ptr);
	eval = protobuf_c_enum_descriptor_get_value(&dnstap__message__type__descriptor, val);
	if (eval == NULL) {
		return (nmsg_res_failure);
	}
	nmsg_strbuf_append(sb, "message_type: %s%s", eval->name, endline);
	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_socket_family(nmsg_message_t msg,
			struct nmsg_msgmod_field *field,
			unsigned val_idx,
			void **data,
			size_t *len,
			void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	*data = (void *)&dnstap->message->socket_family;
	if (len)
		*len = sizeof(dnstap->message->socket_family);

	return (nmsg_res_success);
}

static nmsg_res
dnstap_socket_family_format(nmsg_message_t msg,
			struct nmsg_msgmod_field *field,
			void *ptr,
			struct nmsg_strbuf *sb,
			const char *endline)
{
	const ProtobufCEnumValue *eval;
	int val = *((int *)ptr);
	eval = protobuf_c_enum_descriptor_get_value(&dnstap__socket_family__descriptor, val);
	if (eval == NULL) {
		return (nmsg_res_failure);
	}
	nmsg_strbuf_append_str(sb, eval->name, strlen(eval->name));
	return (nmsg_res_success);
}

static nmsg_res
dnstap_socket_family_print(nmsg_message_t msg,
			struct nmsg_msgmod_field *field,
			void *ptr,
			struct nmsg_strbuf *sb,
			const char *endline)
{
	const ProtobufCEnumValue *eval;
	int val = *((int *)ptr);
	eval = protobuf_c_enum_descriptor_get_value(&dnstap__socket_family__descriptor, val);
	if (eval == NULL) {
		return (nmsg_res_failure);
	}
	nmsg_strbuf_append(sb, "socket_family: %s%s", eval->name, endline);
	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_socket_protocol(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	*data = (void *)&dnstap->message->socket_protocol;
	if (len)
		*len = sizeof(dnstap->message->socket_protocol);

	return (nmsg_res_success);
}

static nmsg_res
dnstap_socket_protocol_format(nmsg_message_t msg,
			struct nmsg_msgmod_field *field,
			void *ptr,
			struct nmsg_strbuf *sb,
			const char *endline)
{
	const ProtobufCEnumValue *eval;
	int val = *((int *)ptr);
	eval = protobuf_c_enum_descriptor_get_value(&dnstap__socket_protocol__descriptor, val);
	if (eval == NULL) {
		return (nmsg_res_failure);
	}
	nmsg_strbuf_append_str(sb, eval->name, strlen(eval->name));
	return (nmsg_res_success);
}

static nmsg_res
dnstap_socket_protocol_print(nmsg_message_t msg,
			struct nmsg_msgmod_field *field,
			void *ptr,
			struct nmsg_strbuf *sb,
			const char *endline)
{
	const ProtobufCEnumValue *eval;
	int val = *((int *)ptr);
	eval = protobuf_c_enum_descriptor_get_value(&dnstap__socket_protocol__descriptor, val);
	if (eval == NULL) {
		return (nmsg_res_failure);
	}
	nmsg_strbuf_append(sb, "socket_protocol: %s%s", eval->name, endline);
	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_address(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	if (!strcmp(field->name, "query_address")) {
		if (!dnstap->message->has_query_address)
			return (nmsg_res_failure);
		*data = (void *)dnstap->message->query_address.data;
		*len = dnstap->message->query_address.len;
	} else if (!strcmp(field->name, "response_address")) {
		if (!dnstap->message->has_response_address)
			return (nmsg_res_failure);
		*data = (void *)dnstap->message->response_address.data;
		*len = dnstap->message->response_address.len;
	} else {
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_port(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	if (!strcmp(field->name, "query_port")) {
		if (!dnstap->message->has_query_port)
			return (nmsg_res_failure);
		*data = (void *)&dnstap->message->query_port;
		if (len)
			*len = sizeof(dnstap->message->query_port);
	} else if (!strcmp(field->name, "response_port")) {
		if (!dnstap->message->has_response_port)
			return (nmsg_res_failure);
		*data = (void *)&dnstap->message->response_port;
		if (len)
			*len = sizeof(dnstap->message->response_port);
	} else {
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_time_sec(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	if (!strcmp(field->name, "query_time_sec")) {
		if (!dnstap->message->has_query_time_sec)
			return (nmsg_res_failure);
		*data = (void *)&dnstap->message->query_time_sec;
		if (len)
			*len = sizeof(dnstap->message->query_time_sec);
	} else if (!strcmp(field->name, "response_time_sec")) {
		if (!dnstap->message->has_response_time_sec)
			return (nmsg_res_failure);
		*data = (void *)&dnstap->message->response_time_sec;
		if (len)
			*len = sizeof(dnstap->message->response_time_sec);
	} else {
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_time_nsec(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	if (!strcmp(field->name, "query_time_nsec")) {
		if (!dnstap->message->has_query_time_nsec)
			return (nmsg_res_failure);
		*data = (void *)&dnstap->message->query_time_nsec;
		if (len)
			*len = sizeof(dnstap->message->query_time_nsec);
	} else if (!strcmp(field->name, "response_time_nsec")) {
		if (!dnstap->message->has_response_time_nsec)
			return (nmsg_res_failure);
		*data = (void *)&dnstap->message->response_time_nsec;
		if (len)
			*len = sizeof(dnstap->message->response_time_nsec);
	} else {
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_query_zone(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	if (!dnstap->message->has_query_zone)
		return (nmsg_res_failure);
	*data = (void *)dnstap->message->query_zone.data;
	*len = dnstap->message->query_zone.len;

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_dns(nmsg_message_t msg,
		    struct nmsg_msgmod_field *field,
		    unsigned val_idx,
		    void **data,
		    size_t *len,
		    void *msg_clos)
{
	Dnstap__Dnstap *dnstap = (Dnstap__Dnstap *)nmsg_message_get_payload(msg);
	if (dnstap == NULL || val_idx != 0 || ! dnstap->message)
		return (nmsg_res_failure);

	if (!strcmp(field->name, "query_message")) {
		if (!dnstap->message->has_query_message)
			return (nmsg_res_failure);
		*data = (void *)dnstap->message->query_message.data;
		*len = dnstap->message->query_message.len;
	} else if (!strcmp(field->name, "response_message")) {
		if (!dnstap->message->has_response_message)
			return (nmsg_res_failure);
		*data = (void *)dnstap->message->response_message.data;
		*len = dnstap->message->response_message.len;
	} else {
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_id(nmsg_message_t m,
	    struct nmsg_msgmod_field *field,
	    unsigned val_idx,
	    void **data,
	    size_t *len,
	    void *msg_clos)
{
	struct dnstap_priv *priv = (struct dnstap_priv *)msg_clos;

	if (val_idx != 0 || priv == NULL || !priv->has_id) {
		return (nmsg_res_failure);
	}

	*data = (void *)&priv->id;
	if (len != NULL)
		*len = sizeof(priv->id);

	return (nmsg_res_success);
}


static nmsg_res
dnstap_get_qname(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		unsigned val_idx,
		void **data,
		size_t *len,
		void *msg_clos)
{
	struct dnstap_priv *priv = (struct dnstap_priv *)msg_clos;

	if (val_idx != 0 || priv == NULL || !priv->has_qname) {
		return (nmsg_res_failure);
	}

	*data = (void *)priv->qname.data;
	if (len != NULL)
		*len = priv->qname.len;

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_qtype(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		unsigned val_idx,
		void **data,
		size_t *len,
		void *msg_clos)
{
	struct dnstap_priv *priv = (struct dnstap_priv *)msg_clos;

	if (val_idx != 0 || priv == NULL || !priv->has_qtype) {
		return (nmsg_res_failure);
	}

	*data = (void *)&priv->qtype;
	if (len != NULL)
		*len = sizeof(priv->qtype);

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_qclass(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		unsigned val_idx,
		void **data,
		size_t *len,
		void *msg_clos)
{
	struct dnstap_priv *priv = (struct dnstap_priv *)msg_clos;

	if (val_idx != 0 || priv == NULL || !priv->has_qclass) {
		return (nmsg_res_failure);
	}

	*data = (void *)&priv->qclass;
	if (len != NULL)
		*len = sizeof(priv->qclass);

	return (nmsg_res_success);
}

static nmsg_res
dnstap_get_rcode(nmsg_message_t m,
		struct nmsg_msgmod_field *field,
		unsigned val_idx,
		void **data,
		size_t *len,
		void *msg_clos)
{
	struct dnstap_priv *priv = (struct dnstap_priv *)msg_clos;

	if (val_idx != 0 || priv == NULL || !priv->has_rcode) {
		return (nmsg_res_failure);
	}

	*data = (void *)&priv->rcode;
	if (len != NULL)
		*len = sizeof(priv->rcode);

	return (nmsg_res_success);
}
