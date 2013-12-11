/*
 * Copyright (c) 2008-2010, 2012, 2013 by Farsight Security, Inc.
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

#ifndef NMSG_RES_H
#define NMSG_RES_H

/*! \file nmsg/res.h
 * \brief Possible result codes for nmsg functions.
 */

/** nmsg result code */
enum nmsg_res {
	nmsg_res_success,		/*%< success */
	nmsg_res_failure,		/*%< generic failure */
	nmsg_res_eof,			/*%< end of file */
	nmsg_res_memfail,		/*%< out of memory */
	nmsg_res_magic_mismatch,	/*%< nmsg header magic incorrect */
	nmsg_res_version_mismatch,	/*%< nmsg header version incorrect */
	nmsg_res_pbuf_ready,		/*%< a pbuf is ready to be written */
	nmsg_res_notimpl,		/*%< module lacks a function */
	nmsg_res_stop,			/*%< processing should stop */
	nmsg_res_again,			/*%< caller should try again */
	nmsg_res_parse_error,		/*%< unable to parse input */
	nmsg_res_pcap_error,		/*%< libpcap error */
	nmsg_res_read_failure,		/*%< read failure */
	nmsg_res_container_full,
	nmsg_res_container_overfull,
	nmsg_res_errno,
};

/**
 * Look up a result code by value.
 *
 * \param[in] val Result code value.
 *
 * \return String describing the result code value. If an unknown result code
 * is passed, the string "(unknown libnmsg result code)" will be returned.
 */
const char *nmsg_res_lookup(enum nmsg_res val);

#endif /* NMSG_RES_H */
