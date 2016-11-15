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

static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_message_type);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_socket_family);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_socket_protocol);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_address);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_port);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_time_sec);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_time_nsec);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_query_zone);
static NMSG_MSGMOD_FIELD_GETTER(dnstap_get_dns);

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
	  .get = dnstap_get_message_type
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "socket_family",
	  .get = dnstap_get_socket_family
        },
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "socket_protocol",
	  .get = dnstap_get_socket_protocol
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
	  .print = dns_name_print
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "response_message",
	  .get = dnstap_get_dns,
	  .print = dnsqr_message_print
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor = NMSG_VENDOR_BASE,
	.msgtype = { NMSG_VENDOR_BASE_DNSTAP_ID, NMSG_VENDOR_BASE_DNSTAP_NAME },
	.pbdescr = &dnstap__dnstap__descriptor,
	.fields = dnstap_fields
};

/* Functions */

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
