/* pbnmsg_isc_email.c - email protobuf nmsg module */

/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#include "email.pb-c.h"

/* Data structures. */

typedef enum {
	mode_keyval,
	mode_headers
} input_mode;

struct email_clos {
	Nmsg__Isc__Email	*eh;
	char			*headers, *headers_cur;
	input_mode		mode;
	size_t			headers_size;
	size_t			size;
};

struct email_types {
	Nmsg__Isc__EmailType	type;
	const char		*name;
};

/* Data. */

struct email_types module_email_types[] = {
	{ NMSG__ISC__EMAIL_TYPE__unknown,	"unknown"	},
	{ NMSG__ISC__EMAIL_TYPE__spamtrap,	"spamtrap"	},
	{ NMSG__ISC__EMAIL_TYPE__rej_network,	"rej_network"	},
	{ NMSG__ISC__EMAIL_TYPE__rej_content,	"rej_content"	},
	{ NMSG__ISC__EMAIL_TYPE__rej_user,	"rej_user"	},
	{ 0, NULL }
};

/* Macros. */

#define MSGTYPE_EMAIL_ID	2
#define MSGTYPE_EMAIL_NAME	"email"

#define DEFAULT_HDRSZ		1024

#define linecmp(line, str) (strncmp(line, str, sizeof(str) - 1) == 0)
#define lineval(line, str) (line + sizeof(str) - 1)

/* Forward. */

static nmsg_res add_field(struct email_clos *, const char *,
			  ProtobufCBinaryData *, protobuf_c_boolean *);
static nmsg_res add_field_ip(struct email_clos *, const char *,
			     ProtobufCBinaryData *, protobuf_c_boolean *);
static nmsg_res add_field_strarray(struct email_clos *, const char *,
				   ProtobufCBinaryData **, size_t *);
static nmsg_res add_field_type(struct email_clos *, const char *,
			       Nmsg__Isc__EmailType *, protobuf_c_boolean *);
static const char *email_type_to_str(Nmsg__Isc__EmailType);
static nmsg_res finalize_pbuf(struct email_clos *, uint8_t **, size_t *);
static size_t trim_newline(char *);
static void reset_eh(struct email_clos *);

/* Exported via module context. */

static void *email_init(int debug);
static nmsg_res email_fini(void *);
static nmsg_res email_pbuf_to_pres(Nmsg__NmsgPayload *, char **pres,
				   const char *endline);
static nmsg_res email_pres_to_pbuf(void *, const char *line,
				   uint8_t **pbuf, size_t *);

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.init = &email_init,
	.fini = &email_fini,
	.pbuf2pres = &email_pbuf_to_pres,
	.pres2pbuf = &email_pres_to_pbuf,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_EMAIL_ID, MSGTYPE_EMAIL_NAME },
		NMSG_IDNAME_END
	}
};

/* Exported via module context. */

static void *
email_init(int debug) {
	struct email_clos *clos;

	if (debug > 2)
		fprintf(stderr, "email: starting module\n");

	clos = calloc(1, sizeof(*clos));
	if (clos == NULL)
		return (NULL);

	clos->headers_cur = clos->headers = calloc(1, DEFAULT_HDRSZ);
	if (clos->headers == NULL) {
		free(clos);
		return (NULL);
	}
	clos->headers_size = DEFAULT_HDRSZ;

	return (clos);
}

static nmsg_res
email_fini(void *cl) {
	struct email_clos *clos = cl;
	free(clos->eh);
	free(clos->headers);
	free(clos);
	return (nmsg_res_success);
}

static nmsg_res
email_pres_to_pbuf(void *cl, const char *line, uint8_t **pbuf, size_t *sz) {
	Nmsg__Isc__Email *eh;
	nmsg_res res;
	struct email_clos *clos;

	clos = (struct email_clos *) cl;
	if (clos->eh == NULL) {
		clos->eh = calloc(1, sizeof(*clos->eh));
		if (clos->eh == NULL)
			return (nmsg_res_memfail);
		nmsg__isc__email__init(clos->eh);
	}

	eh = clos->eh;
	res = nmsg_res_success;

	if (clos->mode == mode_keyval) {
		const char *val;

		if (line[0] == '\n') {
			clos->mode = mode_keyval;
			return (finalize_pbuf(clos, pbuf, sz));
		} else if (!eh->has_type && linecmp(line, "type: ")) {
			val = lineval(line, "type: ");
			res = add_field_type(clos, val, &eh->type,
					     &eh->has_type);
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
			val = lineval(line, "rcpt: ");
			res = add_field_strarray(clos, val, &eh->rcpt,
						 &eh->n_rcpt);
		} else if (linecmp(line, "bodyurl: ")) {
			val = lineval(line, "bodyurl: ");
			res = add_field_strarray(clos, val, &eh->bodyurl,
						 &eh->n_bodyurl);
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

			if ((clos->headers_cur + len + 1) >
			    (clos->headers + clos->headers_size))
			{
				ptrdiff_t cur_offset = clos->headers_cur -
					clos->headers;

				clos->headers = realloc(clos->headers,
							clos->headers_size * 2);
				if (clos->headers == NULL) {
					clos->headers_cur = NULL;
					return (nmsg_res_memfail);
				}
				clos->headers_size *= 2;
				clos->headers_cur = clos->headers + cur_offset;
			}

			eh->has_headers = true;
			strncpy(clos->headers_cur, line, len);
			clos->headers_cur[len] = '\0';
			clos->headers_cur += len;
			clos->size += len;
		}
	}

	return (nmsg_res_success);
}

static nmsg_res
add_field(struct email_clos *clos, const char *val,
	  ProtobufCBinaryData *field, protobuf_c_boolean *has)
{
	char *s;

	s = strdup(val);
	if (s == NULL)
		return (nmsg_res_memfail);
	field->len = trim_newline(s) + 1;
	field->data = (uint8_t *) s;
	*has = true;

	clos->size += field->len;

	return (nmsg_res_success);
}

static nmsg_res
add_field_strarray(struct email_clos *clos, const char *val,
		   ProtobufCBinaryData **field, size_t *n)
{
	char *s;

	s = strdup(val);
	if (s == NULL)
		return (nmsg_res_memfail);
	*field = realloc(*field, (*n + 1) * sizeof(ProtobufCBinaryData));
	if (*field == NULL) {
		free(s);
		return (nmsg_res_memfail);
	}

	(*field)[*n].len = trim_newline(s) + 1;
	(*field)[*n].data = (uint8_t *) s;
	clos->size += (*field)[*n].len;
	*n += 1;

	return (nmsg_res_success);
}

static nmsg_res
add_field_ip(struct email_clos *clos, const char *sip,
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
		field->data = malloc(4);
		if (field->data == NULL) {
			free(s);
			return (nmsg_res_memfail);
		}
		memcpy(field->data, ip, 4);
		field->len = 4;
		*has = true;
		clos->size += 4;
	} else if (inet_pton(AF_INET6, s, ip) == 1) {
		field->data = malloc(16);
		if (field->data == NULL) {
			free(s);
			return (nmsg_res_memfail);
		}
		memcpy(field->data, ip, 16);
		field->len = 16;
		*has = true;
		clos->size += 16;
	}
	free(s);

	return (nmsg_res_success);
}

static nmsg_res
add_field_type(struct email_clos *clos, const char *val,
	       Nmsg__Isc__EmailType *field, protobuf_c_boolean *has)
{
	struct email_types *et;

	for (et = module_email_types;
	     et->name != NULL;
	     et++)
	{
		if (strncasecmp(val, et->name, strlen(et->name)) == 0) {
			*field = et->type;
			*has = true;
			clos->size += 2;
			return (nmsg_res_success);
		}
	}
	return (nmsg_res_failure);
}

static const char *
email_type_to_str(Nmsg__Isc__EmailType type) {
	struct email_types *et;

	for (et = module_email_types;
	     et->name != NULL;
	     et++)
	{
		if (type == et->type)
			return (et->name);
	}
	return ("UNKNOWN");
}

static nmsg_res
email_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Email *eh;
	char sip[INET6_ADDRSTRLEN];
	char *old_bodyurls = NULL, *bodyurls = NULL;
	char *old_rcpts = NULL, *rcpts = NULL;
	unsigned i;

	if (np->has_payload == 0)
		return (nmsg_res_failure);
	eh = nmsg__isc__email__unpack(NULL, np->payload.len,
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
	for (i = 0; i < eh->n_bodyurl; i++) {
		nmsg_asprintf(&bodyurls, "%sbodyurl: %s%s",
			      old_bodyurls != NULL ? old_bodyurls : "",
			      eh->bodyurl[i].data,
			      el);
		free(old_bodyurls);
		old_bodyurls = bodyurls;
	}
	nmsg_asprintf(pres,
		      "%s%s%s"
		      "%s%s%s"
		      "%s%s%s"
		      "%s%s%s"
		      "%s%s%s"
		      "%s"
		      "%s%s%s%s%s"
		      "%s"
		      "\n"
		      ,
		      eh->has_type ? "type: " : "",
		      eh->has_type ? email_type_to_str(eh->type) : "",
		      eh->has_type ? el : "",

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
		      bodyurls != NULL ? bodyurls : "",

		      eh->has_headers ? "headers:" : "",
		      eh->has_headers ? el : "",
		      eh->has_headers ? (char *) eh->headers.data : "",
		      eh->has_headers ? "." : "",
		      eh->has_headers ? el : ""
	);

	free(rcpts);
	free(bodyurls);
	nmsg__isc__email__free_unpacked(eh, NULL);

	return (nmsg_res_success);
}

/* Private. */

static nmsg_res
finalize_pbuf(struct email_clos *clos, uint8_t **pbuf, size_t *sz) {
	*pbuf = malloc(2 * clos->size);
	if (*pbuf == NULL) {
		reset_eh(clos);
		return (nmsg_res_memfail);
	}
	if (clos->eh->has_headers == true) {
		clos->eh->headers.data = (uint8_t *) clos->headers;
		/* this string needs to be \0 terminated,
		 * so add 1 to strlen() */
		clos->eh->headers.len = strlen(clos->headers) + 1;
	}
	if (clos->eh->has_type == false) {
		clos->eh->type = NMSG__ISC__EMAIL_TYPE__unknown;
		clos->eh->has_type = true;
	}
	*sz = nmsg__isc__email__pack(clos->eh, *pbuf);
	reset_eh(clos);
	return (nmsg_res_pbuf_ready);
}

static void
reset_eh(struct email_clos *clos) {
	unsigned i;

	for (i = 0; i < clos->eh->n_rcpt; i++)
		free(clos->eh->rcpt[i].data);
	free(clos->eh->rcpt);

	for (i = 0; i < clos->eh->n_bodyurl; i++)
		free(clos->eh->bodyurl[i].data);
	free(clos->eh->bodyurl);

	free(clos->eh->from.data);
	free(clos->eh->helo.data);
	free(clos->eh->srcip.data);
	free(clos->eh->srchost.data);
	free(clos->eh);
	clos->eh = NULL;
	if (clos->headers_size > DEFAULT_HDRSZ)
		clos->headers = realloc(clos->headers, DEFAULT_HDRSZ);
	clos->headers_cur = clos->headers;
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
