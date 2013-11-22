/*
 * Copyright (c) 2009, 2010, 2012 by Farsight Security, Inc.
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

#include "private.h"

static const char *res_strings[] = {
	[nmsg_res_success]		= "success",
	[nmsg_res_failure]		= "generic failure",
	[nmsg_res_eof]			= "end of file",
	[nmsg_res_memfail]		= "memory allocation failed",
	[nmsg_res_magic_mismatch]	= "incorrect magic number in NMSG header",
	[nmsg_res_version_mismatch]	= "incorrect version number in NMSG header",
	[nmsg_res_pbuf_ready]		= "pbuf payload ready",
	[nmsg_res_notimpl]		= "function not implemented",
	[nmsg_res_stop]			= "stop condition reached",
	[nmsg_res_again]		= "call should be repeated again",
	[nmsg_res_parse_error]		= "parse error",
	[nmsg_res_pcap_error]		= "libpcap error",
	[nmsg_res_read_failure]		= "read failure",
	[nmsg_res_container_full]	= "NMSG container is full",
	[nmsg_res_container_overfull]	= "NMSG container is overfull"
};

const char *
nmsg_res_lookup(enum nmsg_res val) {
	if (val > sizeof(res_strings) / sizeof(char *))
		return (NULL);
	return res_strings[val];
}
