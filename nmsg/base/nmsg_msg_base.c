/* nmsg_msg_base.c - base nmsg_msg modules */

/*
 * Copyright (c) 2008-2012 by Farsight Security, Inc.
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

#include "nmsg_port_net.h"

#include <nmsg.h>
#include <nmsg/msgmod_plugin.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_email
#include "email.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_http
#include "http.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_ipconn
#include "ipconn.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_linkpair
#include "linkpair.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_logline
#include "logline.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_ncap
#include "ncap.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_dns
#include "dns.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_pkt
#include "pkt.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_dnsqr
#include "dnsqr.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_xml
#include "xml.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_encode
#include "encode.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_packet
#include "packet.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_dnstap
#include "dnstap.c"
#undef nmsg_msgmod_ctx

#define nmsg_msgmod_ctx nmsg_msgmod_ctx_dnsobs
#include "dnsobs.c"
#undef msg_msgmod_ctx

/* Export. */

struct nmsg_msgmod_plugin *nmsg_msgmod_ctx_array[] = {
	&nmsg_msgmod_ctx_email,
	&nmsg_msgmod_ctx_http,
	&nmsg_msgmod_ctx_ipconn,
	&nmsg_msgmod_ctx_linkpair,
	&nmsg_msgmod_ctx_logline,
	&nmsg_msgmod_ctx_ncap,
	&nmsg_msgmod_ctx_dns,
	&nmsg_msgmod_ctx_pkt,
	&nmsg_msgmod_ctx_dnsqr,
	&nmsg_msgmod_ctx_xml,
	&nmsg_msgmod_ctx_encode,
	&nmsg_msgmod_ctx_packet,
	&nmsg_msgmod_ctx_dnstap,
	&nmsg_msgmod_ctx_dnsobs,
	NULL
};
