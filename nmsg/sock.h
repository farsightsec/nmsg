/*
 * Copyright (c) 2010-2015 by Farsight Security, Inc.
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

#ifndef NMSG_SOCK_H
#define NMSG_SOCK_H

/*! \file nmsg/sock.h
 * \brief Socket utilities.
 */

/**
 * Parse an IP address and port number into a sockaddr.
 *
 * \param[in] af Address family (AF_INET or AF_INET6).
 * \param[in] addr Network address.
 * \param[in] port Network port.
 * \param[in] sai Caller-allocated sockaddr_in structure.
 * \param[in] sai6 Caller-allocated sockaddr_in6 structure.
 * \param[out] sa Will be set to point to either sai or sai6.
 * \param[out] salen Length of sa.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_parse_error
 */
nmsg_res
nmsg_sock_parse(int af, const char *addr, unsigned port,
		struct sockaddr_in *sai,
		struct sockaddr_in6 *sai6,
		struct sockaddr **sa,
		socklen_t *salen);

/**
 * Parse a "socket spec" string.
 *
 * \param[in] sockspec The "socket spec" string.
 * \param[out] af Address family (AF_INET or AF_INET6).
 * \param[out] addr Network address. Dynamically allocated; must be
 *	freed with free().
 * \param[out] port_start Start of network port range.
 * \param[out] port_end End of network port range.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_sock_parse_sockspec(const char *sockspec, int *af, char **addr,
			 unsigned *port_start, unsigned *port_end);

#endif /* NMSG_SOCK_H */
