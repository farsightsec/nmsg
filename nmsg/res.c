/*
 * Copyright (c) 2009-2015 by Farsight Security, Inc.
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

const char *
nmsg_res_lookup(enum nmsg_res res)
{
	switch (res) {
	case nmsg_res_success:
		return "success";
	case nmsg_res_failure:
		return "generic failure";
	case nmsg_res_eof:
		return "end of file";
	case nmsg_res_memfail:
		return "memory allocation failed";
	case nmsg_res_magic_mismatch:
		return "incorrect magic number in NMSG header";
	case nmsg_res_version_mismatch:
		return "incorrect version number in NMSG header";
	case nmsg_res_pbuf_ready:
		return "pbuf payload ready";
	case nmsg_res_notimpl:
		return "function not implemented";
	case nmsg_res_stop:
		return "stop condition reached";
	case nmsg_res_again:
		return "call should be repeated again";
	case nmsg_res_parse_error:
		return "parse error";
	case nmsg_res_pcap_error:
		return "libpcap error";
	case nmsg_res_read_failure:
		return "read failure";
	case nmsg_res_container_full:
		return "NMSG container is full";
	case nmsg_res_container_overfull:
		return "NMSG container is overfull";
	case nmsg_res_errno:
		return "consult errno";
	}
	return "(unknown libnmsg result code)";
}
