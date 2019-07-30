/*
 * Copyright (c) 2012-2019 by Farsight Security, Inc.
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

#include "private.h"

#ifdef HAVE_LIBZMQ

/* Private declarations. */

typedef enum {
	sockdir_invalid,
	sockdir_accept,
	sockdir_connect,
} sockdir_t;

typedef enum {
	socktype_invalid,
	socktype_pubsub,
	socktype_pushpull,
} socktype_t;

/* Forward. */

static bool
munge_endpoint(const char *, char **, sockdir_t *, socktype_t *);

static bool
set_options(void *, int);

/* Private. */

static bool
munge_endpoint(const char *ep, char **s_ep, sockdir_t *s_dir, socktype_t *s_type) {
	char *s, *saveptr, *tok;
	bool found_sockdir = false;
	bool found_socktype = false;

	s = strdup(ep);
	assert(s != NULL);

	*s_ep = strtok_r(s, ",", &saveptr);
	if (*s_ep == NULL) {
		free(s);
		return (false);
	}
	while ((tok = strtok_r(NULL, ",", &saveptr)) != NULL) {
		if (strcasecmp(tok, "accept") == 0) {
			if (found_sockdir) return (false);
			found_sockdir = true;
			*s_dir = sockdir_accept;
		} else if (strcasecmp(tok, "connect") == 0) {
			if (found_sockdir) return (false);
			found_sockdir = true;
			*s_dir = sockdir_connect;
		} else if (strcasecmp(tok, "pubsub") == 0) {
			if (found_socktype) return (false);
			found_socktype = true;
			*s_type = socktype_pubsub;
		} else if (strcasecmp(tok, "pushpull") == 0) {
			if (found_socktype) return (false);
			found_socktype = true;
			*s_type = socktype_pushpull;
		}
	}

	return (true);
}

static bool
set_options(void *s, int socket_type) {
	static const int i_thousand = 1000;

	if (socket_type == ZMQ_SUB) {
		if (zmq_setsockopt(s, ZMQ_SUBSCRIBE, "NMSG", 4))
			return (false);
	} else if (socket_type == ZMQ_PUB || socket_type == ZMQ_PUSH) {
		if (zmq_setsockopt(s, ZMQ_SNDHWM, &i_thousand, sizeof(i_thousand)))
			return (false);
		if (zmq_setsockopt(s, ZMQ_LINGER, &i_thousand, sizeof(i_thousand)))
			return (false);
	}

	return (true);
}

/* Export. */

nmsg_input_t
nmsg_input_open_zmq_endpoint(void *zmq_ctx, const char *ep) {
	nmsg_input_t input = NULL;
	int socket_type = 0;
	sockdir_t s_dir = sockdir_accept;
	socktype_t s_type = socktype_pubsub;
	char *s_ep = NULL;
	void *s;

	if (!munge_endpoint(ep, &s_ep, &s_dir, &s_type) || !s_ep)
		goto out;

	assert(s_dir == sockdir_accept || s_dir == sockdir_connect);
	assert(s_type == socktype_pubsub || s_type == socktype_pushpull);

	if (s_type == socktype_pubsub)
		socket_type = ZMQ_SUB;
	else if (s_type == socktype_pushpull)
		socket_type = ZMQ_PULL;

	s = zmq_socket(zmq_ctx, socket_type);
	if (!s) goto out;
	if (!set_options(s, socket_type)) {
		zmq_close(s);
		goto out;
	}

	if (s_dir == sockdir_accept) {
		if (zmq_bind(s, s_ep) == -1) {
			zmq_close(s);
			goto out;
		}
	} else if (s_dir == sockdir_connect) {
		if (zmq_connect(s, s_ep) == -1) {
			zmq_close(s);
			goto out;
		}
	}

	input = nmsg_input_open_zmq(s);
out:
	free(s_ep);
	return (input);
}

nmsg_output_t
nmsg_output_open_zmq_endpoint(void *zmq_ctx, const char *ep, size_t bufsz) {
	nmsg_output_t output = NULL;
	int socket_type = 0;
	sockdir_t s_dir = sockdir_connect;
	socktype_t s_type = socktype_pubsub;
	char *s_ep = NULL;
	void *s;

	if (!munge_endpoint(ep, &s_ep, &s_dir, &s_type) || !s_ep)
		goto out;

	assert(s_dir == sockdir_accept || s_dir == sockdir_connect);
	assert(s_type == socktype_pubsub || s_type == socktype_pushpull);

	if (s_type == socktype_pubsub)
		socket_type = ZMQ_PUB;
	else if (s_type == socktype_pushpull)
		socket_type = ZMQ_PUSH;

	s = zmq_socket(zmq_ctx, socket_type);
	if (!s) goto out;
	if (!set_options(s, socket_type)) {
		zmq_close(s);
		goto out;
	}

	if (s_dir == sockdir_accept) {
		if (zmq_bind(s, s_ep) == -1) {
			zmq_close(s);
			goto out;
		}
	} else if (s_dir == sockdir_connect) {
		if (zmq_connect(s, s_ep) == -1) {
			zmq_close(s);
			goto out;
		}
	}

	output = nmsg_output_open_zmq(s, bufsz);
out:
	free(s_ep);
	return (output);
}

#else /* HAVE_LIBZMQ */

/* Export. */

nmsg_input_t
nmsg_input_open_zmq_endpoint(void *zmq_ctx __attribute__((unused)),
			    const char *ep __attribute__((unused)))
{
	return (NULL);
}

nmsg_output_t
nmsg_output_open_zmq_endpoint(void *zmq_ctx __attribute__((unused)),
			     const char *ep __attribute__((unused)),
			     size_t bufsz __attribute__((unused)))
{
	return (NULL);
}

#endif /* HAVE_LIBZMQ */
