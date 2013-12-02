/* XML nmsg message module */

/*
 * Copyright (c) 2010 by Farsight Security, Inc.
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

#include "xml.pb-c.h"

/* Data. */

struct nmsg_msgmod_field xml_fields[] = {
	{
		.type = nmsg_msgmod_ft_string,
		.name = "xmltype",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	{
		.type = nmsg_msgmod_ft_bytes,
		.name = "xmlpayload",
		.flags = NMSG_MSGMOD_FIELD_REQUIRED
	},
	NMSG_MSGMOD_FIELD_END
};

/* Export. */

struct nmsg_msgmod_plugin nmsg_msgmod_ctx = {
	NMSG_MSGMOD_REQUIRED_INIT,
	.vendor		= NMSG_VENDOR_BASE,
	.msgtype	= { NMSG_VENDOR_BASE_XML_ID, NMSG_VENDOR_BASE_XML_NAME },

	.pbdescr	= &nmsg__base__xml__descriptor,
	.fields		= xml_fields
};
