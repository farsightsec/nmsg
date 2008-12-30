/* pbnmsg_isc_emailhdr.c - emailhdr protobuf nmsg module */

/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include "nmsg_port.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/asprintf.h>
#include <nmsg/pbmod.h>

#include "emailhdr.pb-c.h"

/* Data structures. */

typedef enum {
	mode_keyval,
	mode_headers,
	mode_skip
} input_mode;

struct emailhdr_clos {
	Nmsg__Isc__Emailhdr	*eh;
	char			*headers, *headers_cur;
	input_mode		mode;
	size_t			max;
	ssize_t			rem;
};

/* Macros. */

#define MSGTYPE_EMAILHDR_ID	2
#define MSGTYPE_EMAILHDR_NAME	"emailhdr"

#define PAYLOAD_MAXSZ		1208

#define linecmp(line, str) (strncmp(line, str, sizeof(str) - 1) == 0)
#define lineval(line, str) (line + sizeof(str) - 1)

/* Forward. */

static bool rem_avail(ssize_t rem, size_t len);
static nmsg_res add_field(struct emailhdr_clos *, const char *,
			  ProtobufCBinaryData *, protobuf_c_boolean *);
static nmsg_res add_field_ip(struct emailhdr_clos *, const char *,
			     ProtobufCBinaryData *, protobuf_c_boolean *);
static nmsg_res finalize_pbuf(struct emailhdr_clos *, uint8_t **pbuf, size_t *);
static size_t trim_newline(char *);
static void reset_eh(struct emailhdr_clos *);

/* Exported via module context. */

static void *emailhdr_init(size_t max, int debug);
static nmsg_res emailhdr_fini(void *);
static nmsg_res emailhdr_pbuf_to_pres(Nmsg__NmsgPayload *, char **pres,
				      const char *endline);
static nmsg_res emailhdr_pres_to_pbuf(void *, const char *line,
				      uint8_t **pbuf, size_t *);

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.init = &emailhdr_init,
	.fini = &emailhdr_fini,
	.pbuf2pres = &emailhdr_pbuf_to_pres,
	.pres2pbuf = &emailhdr_pres_to_pbuf,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_EMAILHDR_ID, MSGTYPE_EMAILHDR_NAME },
		NMSG_IDNAME_END
	}
};

/* Exported via module context. */

static void *
emailhdr_init(size_t max, int debug) {
	struct emailhdr_clos *clos;

	if (debug > 2)
		fprintf(stderr, "emailhdr: starting module\n");

	clos = calloc(1, sizeof(*clos));
	if (clos == NULL)
		return (NULL);

	clos->max = (max > PAYLOAD_MAXSZ) ? PAYLOAD_MAXSZ : max;
	clos->rem = clos->max;

	clos->headers_cur = clos->headers = calloc(1, clos->max);
	if (clos->headers == NULL)
		return (NULL);

	return (clos);
}

static nmsg_res
emailhdr_fini(void *cl) {
	struct emailhdr_clos *clos = cl;
	free(clos->eh);
	free(clos->headers);
	free(clos);
	return (nmsg_res_success);
}

static nmsg_res
emailhdr_pres_to_pbuf(void *cl, const char *line, uint8_t **pbuf, size_t *sz) {
	Nmsg__Isc__Emailhdr *eh;
	nmsg_res res;
	struct emailhdr_clos *clos;

	clos = (struct emailhdr_clos *) cl;
	if (clos->eh == NULL) {
		clos->eh = calloc(1, sizeof(*clos->eh));
		if (clos->eh == NULL)
			return (nmsg_res_memfail);
		clos->eh->base.descriptor = &nmsg__isc__emailhdr__descriptor;
	}

	eh = clos->eh;
	res = nmsg_res_success;

	if (clos->mode == mode_skip) {
		if (line[0] == '\n')
			clos->mode = mode_keyval;
		return (res);
	} else if (clos->mode == mode_keyval) {
		char *s;
		const char *val;

		if (line[0] == '\n') {
			clos->mode = mode_keyval;
			return (finalize_pbuf(clos, pbuf, sz));
		} else if (!eh->has_srcip && linecmp(line, "srcip: ")) {
			val = lineval(line, "srcip: ");
			res = add_field_ip(clos, val, &eh->srcip,
					   &eh->has_srcip);
		} else if (!eh->has_srchost && linecmp(line, "srchost: ")) {
			val = lineval(line, "srchost: ");
			res = add_field(clos, val, &eh->srchost,
					&eh->has_srchost);
		} else if (!eh->has_helo && linecmp(line, "helo: ")) {
			val = lineval(line, "helo: ");
			res = add_field(clos, val, &eh->helo, &eh->has_helo);
		} else if (!eh->has_from && linecmp(line, "from: ")) {
			val = lineval(line, "from: ");
			res = add_field(clos, val, &eh->from, &eh->has_from);
		} else if (linecmp(line, "rcpt: ")) {
			s = strdup(lineval(line, "rcpt: "));
			if (s == NULL)
				return (nmsg_res_memfail);
			eh->rcpt = realloc(eh->rcpt, (eh->n_rcpt + 1) *
					   sizeof(ProtobufCBinaryData));
			if (eh->rcpt == NULL) {
				free(s);
				return (nmsg_res_memfail);
			}
			eh->rcpt[eh->n_rcpt].len = trim_newline(s) + 1;
			eh->rcpt[eh->n_rcpt].data = (uint8_t *) s;
			eh->n_rcpt += 1;
		} else if (clos->headers == clos->headers_cur &&
			   linecmp(line, "headers:"))
		{
			clos->mode = mode_headers;
		}
	} else if (clos->mode == mode_headers) {
		if (linecmp(line, ".\n")) {
			clos->mode = mode_keyval;
		} else {
			size_t len = strlen(line);

			if ((signed) len > clos->rem) {
				clos->mode = mode_skip;
				res = nmsg_res_trunc;
			} else {
				eh->has_headers = true;
				clos->rem -= len;
				strncpy(clos->headers_cur, line, len);
				clos->headers_cur[len] = '\0';
				clos->headers_cur += len;
			}
		}
	}

	if (res == nmsg_res_trunc) {
		clos->mode = mode_skip;
		eh->truncated = true;
		return (finalize_pbuf(clos, pbuf, sz));
	}

	return (nmsg_res_success);
}

static nmsg_res
add_field(struct emailhdr_clos *clos, const char *val,
	  ProtobufCBinaryData *field, protobuf_c_boolean *has)
{
	char *s;

	s = strdup(val);
	if (s == NULL)
		return (nmsg_res_memfail);
	field->len = trim_newline(s) + 1;
	if (rem_avail(clos->rem, field->len) == true) {
		clos->rem -= field->len;
	} else {
		free(s);
		return (nmsg_res_trunc);
	}
	field->data = (uint8_t *) s;
	*has = true;

	return (nmsg_res_success);
}

static nmsg_res
add_field_ip(struct emailhdr_clos *clos, const char *sip,
	     ProtobufCBinaryData *field, protobuf_c_boolean *has)
{
	char *s;
	char ip[16];
	nmsg_res res;

	res = nmsg_res_success;
	s = strdup(sip);
	if (s == NULL)
		return (nmsg_res_memfail);
	trim_newline(s);

	if (inet_pton(AF_INET, s, ip) == 1) {
		if (rem_avail(clos->rem, 4) == true) {
			field->data = malloc(4);
			if (field->data == NULL) {
				free(s);
				return (nmsg_res_memfail);
			}
			memcpy(field->data, ip, 4);
			clos->rem -= 4;
			field->len = 4;
			*has = true;
		} else {
			res = nmsg_res_trunc;
		}
	} else if (inet_pton(AF_INET6, s, ip) == 1) {
		if (rem_avail(clos->rem, 16) == true) {
			field->data = malloc(16);
			if (field->data == NULL) {
				free(s);
				return (nmsg_res_memfail);
			}
			memcpy(field->data, ip, 16);
			clos->rem -= 16;
			field->len = 16;
			*has = true;
		} else {
			res = nmsg_res_trunc;
		}
	}
	free(s);

	return (nmsg_res_success);
}

static nmsg_res
emailhdr_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Emailhdr *eh;
	char sip[INET6_ADDRSTRLEN];
	char *old_rcpts = NULL, *rcpts = NULL;
	unsigned i;

	if (np->has_payload == 0)
		return (nmsg_res_failure);
	eh = nmsg__isc__emailhdr__unpack(NULL, np->payload.len,
					 np->payload.data);
	if (eh->has_srcip == true) {
		if (eh->srcip.len == 4) {
			inet_ntop(AF_INET, eh->srcip.data, sip, sizeof(sip));
			if (sip == NULL)
				eh->has_srcip = false;
		} else if (eh->srcip.len == 16) {
			inet_ntop(AF_INET6, eh->srcip.data, sip, sizeof(sip));
			if (sip == NULL)
				eh->has_srcip = false;
		}
	}
	for (i = 0; i < eh->n_rcpt; i++) {
		nmsg_asprintf(&rcpts, "%srcpt: %s%s",
			      old_rcpts != NULL ? old_rcpts : "",
			      eh->rcpt[i].data,
			      el);
		free(old_rcpts);
		old_rcpts = rcpts;
	}
	nmsg_asprintf(pres,
		 "%s%s%s"
		 "%s%s%s"
		 "%s%s%s"
		 "%s%s%s"
		 "%s"
		 "%s%s%s%s%s"
		 "\n"
		 ,
		 eh->has_srcip ? "srcip: " : "",
		 eh->has_srcip ? sip : "",
		 eh->has_srcip ? el : "",

		 eh->has_srchost ? "srchost: " : "",
		 eh->has_srchost ? (char *) eh->srchost.data : "",
		 eh->has_srchost ? el : "",

		 eh->has_helo ? "helo: " : "",
		 eh->has_helo ? (char *) eh->helo.data : "",
		 eh->has_helo ? el : "",

		 eh->has_from ? "from: " : "",
		 eh->has_from ? (char *) eh->from.data : "",
		 eh->has_from ? el : "",

		 rcpts != NULL ? rcpts : "",

		 eh->has_headers ? "headers:" : "",
		 eh->has_headers ? el : "",
		 eh->has_headers ? (char *) eh->headers.data : "",
		 eh->has_headers ? "." : "",
		 eh->has_headers ? el : ""
	);

	free(rcpts);
	nmsg__isc__emailhdr__free_unpacked(eh, NULL);

	return (nmsg_res_success);
}

/* Private. */

static nmsg_res
finalize_pbuf(struct emailhdr_clos *clos, uint8_t **pbuf, size_t *sz) {
	*pbuf = malloc(2 * clos->max);
	if (*pbuf == NULL)
		return (nmsg_res_memfail);
	if (clos->eh->has_headers == true) {
		clos->eh->headers.data = (uint8_t *) clos->headers;
		/* this string needs to be \0 terminated,
		 * so add 1 to strlen() */
		clos->eh->headers.len = strlen(clos->headers) + 1;
	}
	*sz = nmsg__isc__emailhdr__pack(clos->eh, *pbuf);
	reset_eh(clos);
	return (nmsg_res_pbuf_ready);
}

static bool
rem_avail(ssize_t rem, size_t len) {
	if (rem - (ssize_t) len > 0)
		return (true);
	return (false);
}

static void
reset_eh(struct emailhdr_clos *clos) {
	unsigned i;

	for (i = 0; i < clos->eh->n_rcpt; i++)
		free(clos->eh->rcpt[i].data);
	free(clos->eh->rcpt);

	free(clos->eh->from.data);
	free(clos->eh->helo.data);
	free(clos->eh->srcip.data);
	free(clos->eh->srchost.data);
	free(clos->eh);
	clos->eh = NULL;
	clos->rem = clos->max;
}

static size_t
trim_newline(char *line) {
	size_t len;

	len = strlen(line);
	if (line[len - 1] == '\n') {
		line[len - 1] = '\0';
		len -= 1;
	}
	return (len);
}
