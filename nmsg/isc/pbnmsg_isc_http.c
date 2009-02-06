/* pbnmsg_isc_http.c - http protobuf nmsg module */

/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
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
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/asprintf.h>
#include <nmsg/pbmod.h>

#include "http.pb-c.h"

/* Data structures. */

struct http_clos {
	Nmsg__Isc__Http		*h;
	size_t			size;
};

struct http_type {
	Nmsg__Isc__HttpType	type;
	const char		*name;
};

/* Data. */

struct http_type module_http_types[] = {
	{ NMSG__ISC__HTTP_TYPE__unknown,	"unknown"	},
	{ NMSG__ISC__HTTP_TYPE__sinkhole,	"sinkhole"	},
	{ 0, NULL }
};

/* Forward. */

static const char *http_type_to_str(Nmsg__Isc__HttpType);
static nmsg_res finalize_pbuf(struct http_clos *, uint8_t **pbuf, size_t *);

/* Exported via module context. */

static void *http_init(int debug);
static nmsg_res http_fini(void *);
static nmsg_res http_pbuf_to_pres(Nmsg__NmsgPayload *, char **pres,
				  const char *endline);
static nmsg_res http_field_to_pbuf(void *, const char *field,
				   const uint8_t *val, size_t len,
				   uint8_t **pbuf, size_t *);

/* Macros. */

#define MSGTYPE_HTTP_ID		4
#define MSGTYPE_HTTP_NAME	"http"

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.init = &http_init,
	.fini = &http_fini,
	.pbuf2pres = &http_pbuf_to_pres,
	.field2pbuf = &http_field_to_pbuf,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_HTTP_ID, MSGTYPE_HTTP_NAME },
		NMSG_IDNAME_END
	}
};

/* Exported via module context. */

static void *
http_init(int debug) {
	struct http_clos *clos;
	if (debug > 2)
		fprintf(stderr, "http: starting module\n");

	clos = calloc(1, sizeof(*clos));
	return (clos);
}

static nmsg_res
http_fini(void *clos) {
	free(clos);
	return (nmsg_res_success);
}

static nmsg_res
http_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Http *http;
	char srcip[INET6_ADDRSTRLEN], dstip[INET6_ADDRSTRLEN];
	char *srcport = NULL, *dstport = NULL;

	if (np->has_payload == 0)
		return (nmsg_res_failure);
	http = nmsg__isc__http__unpack(NULL, np->payload.len,
				       np->payload.data);

	if (http->has_srcport)
		nmsg_asprintf(&srcport, "srcport: %hu%s",
			      (uint16_t) http->srcport,
			      el);
	if (http->has_dstport)
		nmsg_asprintf(&dstport, "dstport: %hu%s",
			      (uint16_t) http->dstport,
			      el);

	if (http->has_srcip == true) {
		const char *p = NULL;
		if (http->srcip.len == 4) {
			p = inet_ntop(AF_INET, http->srcip.data,
				      srcip, sizeof(srcip));
		} else if (http->srcip.len == 16) {
			p = inet_ntop(AF_INET6, http->srcip.data,
				      srcip, sizeof(srcip));
		}
		if (p == NULL)
			http->has_srcip = false;
	}
	if (http->has_dstip == true) {
		const char *p = NULL;
		if (http->dstip.len == 4) {
			p = inet_ntop(AF_INET, http->dstip.data,
				      dstip, sizeof(dstip));
		} else if (http->dstip.len == 16) {
			p = inet_ntop(AF_INET6, http->dstip.data,
				      dstip, sizeof(dstip));
		}
		if (p == NULL)
			http->has_dstip = false;
	}

	nmsg_asprintf(pres,
		      "type: %s%s"
		      "%s%s%s"		/* srchost */
		      "%s%s%s"		/* srcip */
		      "%s"		/* srcport */
		      "%s%s%s"		/* dstip */
		      "%s"		/* dstport */
		      "%s%s%s%s%s"	/* request */
		      "%s%s%s%s%s"	/* p0f results */
		      "\n"
		      ,
		      http_type_to_str(http->type), el,

		      http->has_srchost	? "srchost: " : "",
		      http->has_srchost	? (char *) http->srchost.data : "",
		      http->has_srchost	? el : "",

		      http->has_srcip	? "srcip: " : "",
		      http->has_srcip	? srcip : "",
		      http->has_srcip	? el : "",

		      srcport != NULL	? srcport : "",

		      http->has_dstip	? "dstip: " : "",
		      http->has_dstip	? dstip : "",
		      http->has_dstip	? el : "",

		      dstport != NULL	? dstport : "",

		      http->has_request	? "request:" : "",
		      http->has_request	? el : "",
		      http->has_request	? (char *) http->request.data : "",
		      http->has_request	? "." : "",
		      http->has_request	? el : "",

		      http->has_p0f	? "p0f:" : "",
		      http->has_p0f	? el : "",
		      http->has_p0f	? (char *) http->p0f.data : "",
		      http->has_p0f	? "." : "",
		      http->has_p0f	? el : ""
	);
	nmsg__isc__http__free_unpacked(http, NULL);
	free(srcport);
	free(dstport);
	return (nmsg_res_success);
}

static nmsg_res
http_field_to_pbuf(void *cl, const char *field, const uint8_t *val,
		       size_t len, uint8_t **pbuf, size_t *sz)
{
	struct http_clos *clos;
	Nmsg__Isc__Http *h;

	clos = (struct http_clos *) cl;
	if (clos->h == NULL) {
		clos->h = calloc(1, sizeof(*clos->h));
		if (clos->h == NULL)
			return (nmsg_res_memfail);
		clos->h->base.descriptor = &nmsg__isc__http__descriptor;
	}
	h = clos->h;

	if (pbuf != NULL && sz != NULL)
		return (finalize_pbuf(clos, pbuf, sz));

	if (strcmp(field, "type") == 0) {
		if (strcmp((char *) val, "sinkhole") == 0)
			h->type = NMSG__ISC__HTTP_TYPE__sinkhole;
		else
			assert(0);
		clos->size += 1;
	} else if (strcmp(field, "srcip") == 0) {
		if (len == 4 || len == 16) {
			h->srcip.data = malloc(len);
			if (h->srcip.data == NULL)
				return (nmsg_res_memfail);
			memcpy(h->srcip.data, val, len);
			h->srcip.len = len;
			clos->size += len;
			h->has_srcip = true;
		}
	} else if (strcmp(field, "dstip") == 0) {
		if (len == 4 || len == 16) {
			h->dstip.data = malloc(len);
			if (h->dstip.data == NULL)
				return (nmsg_res_memfail);
			memcpy(h->dstip.data, val, len);
			h->dstip.len = len;
			clos->size += len;
			h->has_dstip = true;
		}
	} else if (strcmp(field, "srchost") == 0) {
		h->srchost.data = malloc(len);
		if (h->srchost.data == NULL)
			return (nmsg_res_memfail);
		memcpy(h->srchost.data, val, len);
		h->srchost.len = len;
		clos->size += len;
		h->has_srchost = true;
	} else if (strcmp(field, "srcport") == 0) {
		h->srcport = *((uint16_t *) val);
		h->has_srcport = true;
		clos->size += 2;
	} else if (strcmp(field, "dstport") == 0) {
		h->dstport = *((uint16_t *) val);
		h->has_dstport = true;
		clos->size += 2;
	} else if (strcmp(field, "request") == 0) {
		h->request.data = malloc(len);
		if (h->request.data == NULL)
			return (nmsg_res_memfail);
		memcpy(h->request.data, val, len);
		h->request.len = len;
		clos->size += len;
		h->has_request = true;
	}

	return (nmsg_res_success);
}


/* Private. */

static const char *
http_type_to_str(Nmsg__Isc__HttpType type) {
	struct http_type *ht;

	for (ht = module_http_types;
	     ht->name != NULL;
	     ht++)
	{
		if (type == ht->type)
			return (ht->name);
	}
	return ("UNKNOWN");
}


static nmsg_res
finalize_pbuf(struct http_clos *clos, uint8_t **pbuf, size_t *sz) {
	*pbuf = malloc(2 * clos->size);
	if (*pbuf == NULL) {
		free(clos->h);
		return (nmsg_res_memfail);
	}
	*sz = nmsg__isc__http__pack(clos->h, *pbuf);
	free(clos->h->srcip.data);
	free(clos->h->dstip.data);
	free(clos->h->srchost.data);
	free(clos->h->request.data);
	free(clos->h);
	clos->h = NULL;
	clos->size = 0;
	return (nmsg_res_pbuf_ready);
}

