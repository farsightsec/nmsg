/* dnsobs nmsg message module */

/*
 * Copyright (c) 2023 by Farsight Security, Inc.
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

#include "dnsobs.pb-c.h"

/* Exported via module context. */

struct nmsg_msgmod_field dnsobs_fields[] = {
	{
	  .type = nmsg_msgmod_ft_uint64,
	  .name = "time",
	  .flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
	  .type = nmsg_msgmod_ft_ip,
	  .name = "response_ip",
	  .flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "qname",
	  .print = dns_name_print,
	  .format = dns_name_format,
	  .flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
	  .type = nmsg_msgmod_ft_uint16,
	  .name = "qtype",
	  .print = dns_type_print,
	  .format = dns_type_format,
	  .flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
	  .type = nmsg_msgmod_ft_uint16,
	  .name = "qclass",
	  .print = dns_class_print,
	  .format = dns_class_format,
	  .flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
	  .type = nmsg_msgmod_ft_uint16,
	  .name = "rcode",
	  .print = dnsqr_rcode_print,
	  .format = dnsqr_rcode_format,
	  .flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "response",
	  .print = dnsqr_message_print,
	  .format = dnsqr_message_format,
	  .flags = NMSG_MSGMOD_FIELD_FORMAT_RAW,
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "query_zone",
	  .print = dns_name_print,
	  .format = dns_name_format
	},
	{
	  .type = nmsg_msgmod_ft_bytes,
	  .name = "geoid",
	},
	{
	  .type = nmsg_msgmod_ft_uint32,
	  .name = "nsid",
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor = NMSG_VENDOR_BASE,
	.msgtype = { NMSG_VENDOR_BASE_DNSOBS_ID, NMSG_VENDOR_BASE_DNSOBS_NAME },
	.pbdescr = &nmsg__base__dns_obs__descriptor,
	.fields = dnsobs_fields
};
