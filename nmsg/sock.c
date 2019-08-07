/*
 * Copyright (c) 2010, 2012 by Farsight Security, Inc.
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

#include <arpa/inet.h>

#include "private.h"

/* Export. */

nmsg_res
nmsg_sock_parse(int af, const char *addr, unsigned port,
		struct sockaddr_in *sai,
		struct sockaddr_in6 *sai6,
		struct sockaddr **sa,
		socklen_t *salen)
{
	switch (af) {

	case AF_INET:
		if (!inet_pton(AF_INET, addr, &sai->sin_addr))
			return (nmsg_res_parse_error);

		sai->sin_family = AF_INET;
		sai->sin_port = htons(port);
#ifdef HAVE_SA_LEN
		sai->sin_len = sizeof(struct sockaddr_in);
#endif
		*sa = (struct sockaddr *) sai;
		*salen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		if (!inet_pton(AF_INET6, addr, &sai6->sin6_addr))
			return (nmsg_res_parse_error);

		sai6->sin6_family = AF_INET6;
		sai6->sin6_port = htons(port);
#ifdef HAVE_SA_LEN
		sai6->sin6_len = sizeof(struct sockaddr_in6);
#endif
		*sa = (struct sockaddr *) sai6;
		*salen = sizeof(struct sockaddr_in6);
		break;

	default:
		assert(af != AF_INET && af != AF_INET6);
	}

	return (nmsg_res_success);
}

nmsg_res
nmsg_sock_parse_sockspec(const char *sockspec, int *af, char **addr,
			 unsigned *port_start, unsigned *port_end)
{
	char *sock = NULL;
	char *sock_addr = NULL;
	char *t;
	nmsg_res res = nmsg_res_failure;
	int n;
	uint8_t buf[16];

	sock = strdup(sockspec);
	assert(sock != NULL);

	/* tokenize socket address */
	sock_addr = calloc(1, INET6_ADDRSTRLEN);
	assert(sock_addr != NULL);
	t = strchr(sockspec, '/');
	if (t == NULL)
		goto out;
	memcpy(sock_addr, sockspec, t - sockspec);
	sock_addr[t - sockspec] = '\x00';

	/* parse socket address */
	if (inet_pton(AF_INET6, sock_addr, buf)) {
		*af = AF_INET6;
		*addr = strdup(sock_addr);
		if (*addr == NULL)
			goto out;
	} else if (inet_pton(AF_INET, sock_addr, buf)) {
		*af = AF_INET;
		*addr = strdup(sock_addr);
		if (*addr == NULL)
			goto out;
	}

	n = sscanf(t + 1, "%u..%u", port_start, port_end);
	if (n == 1) {
		const char *pptr = t + 1;

		while (*pptr) {

			if (!isdigit(*pptr)) {
				res = nmsg_res_parse_error;
				goto out;
			}

			pptr++;
		}

		*port_end = *port_start;
	} else if (n <= 0)
		goto out;

	/* parsed successfully */
	res = nmsg_res_success;

out:
	free(sock);
	free(sock_addr);
	return (res);
}
