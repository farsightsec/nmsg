/* pbnmsg_isc_linkpair.c - link pair protobuf nmsg module */

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

#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/asprintf.h>
#include <nmsg/pbmod.h>

#include "linkpair.pb-c.h"

/* Data structures. */

struct linkpair_clos {
	Nmsg__Isc__Linkpair	*lp;
	bool			hdrblock;
	char			*headers, *headers_cur;
	size_t			headers_size;
	size_t			size;
};

/* Forward. */

static nmsg_res finalize_pbuf(struct linkpair_clos *, uint8_t **pbuf,
			      size_t *);
static size_t trim_newline(char *);
static void reset_lp(struct linkpair_clos *);

/* Exported via module context. */

static void *linkpair_init(int debug);
static nmsg_res linkpair_fini(void *);
static nmsg_res linkpair_pbuf_to_pres(Nmsg__NmsgPayload *, char **pres,
				      const char *endline);
static nmsg_res linkpair_pres_to_pbuf(void *, const char *line,
				      uint8_t **pbuf, size_t *);
static nmsg_res linkpair_field_to_pbuf(void *, const char *field,
				       const uint8_t *val, size_t len,
				       uint8_t **pbuf, size_t *);

/* Macros. */

#define MSGTYPE_LINKPAIR_ID	3
#define MSGTYPE_LINKPAIR_NAME	"linkpair"

#define DEFAULT_HDRSZ		1024

#define max(x, y) ( (x) < (y) ? (x) : (y) )
#define linecmp(line, str) (strncmp(line, str, sizeof(str) - 1) == 0)
#define lineval(line, str) (line + sizeof(str) - 1)

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.init = &linkpair_init,
	.fini = &linkpair_fini,
	.pbuf2pres = &linkpair_pbuf_to_pres,
	.pres2pbuf = &linkpair_pres_to_pbuf,
	.field2pbuf = &linkpair_field_to_pbuf,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_LINKPAIR_ID, MSGTYPE_LINKPAIR_NAME },
		NMSG_IDNAME_END
	}
};

/* Exported via module context. */

static void *
linkpair_init(int debug) {
	struct linkpair_clos *clos;

	if (debug > 2)
		fprintf(stderr, "linkpair: starting module\n");

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
linkpair_fini(void *cl) {
	struct linkpair_clos *clos = cl;
	free(clos->lp);
	free(clos->headers);
	free(clos);
	return (nmsg_res_success);
}

static nmsg_res
linkpair_pres_to_pbuf(void *cl, const char *line, uint8_t **pbuf, size_t *sz) {
	struct linkpair_clos *clos;

	clos = (struct linkpair_clos *) cl;
	if (clos->lp == NULL) {
		clos->lp = calloc(1, sizeof(*clos->lp));
		if (clos->lp == NULL)
			return (nmsg_res_memfail);
		nmsg__isc__linkpair__init(clos->lp);
	}

	if (clos->hdrblock == false) {
		if (strncmp(line, "type: ", sizeof("type: ") - 1) == 0) {
			const char *stype = line + sizeof("type: ") - 1;

			if (strncmp(stype, "anchor",
				    sizeof("anchor") - 1) == 0)
				clos->lp->type = NMSG__ISC__LINKTYPE__anchor;
			else if (strncmp(stype, "redirect",
					 sizeof("redirect") - 1) == 0)
				clos->lp->type = NMSG__ISC__LINKTYPE__redirect;
		} else if (strncmp(line, "src: ", sizeof("src: ") - 1) == 0) {
			const char *ssrc = line + sizeof("src: ") - 1;

			if (clos->lp->src.data == NULL) {
				char *copy = strdup(ssrc);
				size_t len = trim_newline(copy);

				clos->lp->src.data = (uint8_t *) copy;
				clos->lp->src.len = len + 1;
			}
		} else if (strncmp(line, "dst: ", sizeof("dst: ") - 1) == 0) {
			const char *sdst = line + sizeof("dst: ") - 1;

			if (clos->lp->dst.data == NULL) {
				char *copy = strdup(sdst);
				size_t len = trim_newline(copy);

				clos->lp->dst.data = (uint8_t *) copy;
				clos->lp->dst.len = len + 1;
			}
		} else if (strncmp(line, "headers:",
				   sizeof("headers:") - 1) == 0)
		{
			clos->hdrblock = true;
			clos->lp->has_headers = true;
		} else if (line[0] == '\n') {
			return (finalize_pbuf(clos, pbuf, sz));
		}
	} else if (clos->hdrblock == true) {
		if (linecmp(line, ".\n")) {
			clos->hdrblock = false;
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
			clos->lp->has_headers = true;
			strncpy(clos->headers_cur, line, len);
			clos->headers_cur[len] = '\0';
			clos->headers_cur += len;
			clos->size += len;
		}
	}

	return (nmsg_res_success);
}

static nmsg_res
linkpair_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Linkpair *linkpair;
	const char *linktype;

	if (np->has_payload == 0)
		return (nmsg_res_failure);
	linkpair = nmsg__isc__linkpair__unpack(NULL, np->payload.len,
					       np->payload.data);
	switch (linkpair->type) {
		case NMSG__ISC__LINKTYPE__anchor:
			linktype = "anchor";
			break;
		case NMSG__ISC__LINKTYPE__redirect:
			linktype = "redirect";
			break;
		default:
			linktype = "unknown";
	}

	nmsg_asprintf(pres, "type: %s%ssrc: %s%sdst: %s%s%s%s%s\n",
		      linktype, el,
		      linkpair->src.data, el,
		      linkpair->dst.data, el,
		      linkpair->has_headers ? "headers:\n" : "",
		      linkpair->has_headers ?
			(char *) linkpair->headers.data : "",
		      linkpair->has_headers ? "\n.\n" : "");
	nmsg__isc__linkpair__free_unpacked(linkpair, NULL);
	return (nmsg_res_success);
}

static nmsg_res
linkpair_field_to_pbuf(void *cl, const char *field, const uint8_t *val,
		       size_t len, uint8_t **pbuf, size_t *sz)
{
	struct linkpair_clos *clos;
	Nmsg__Isc__Linkpair *lp;

	clos = (struct linkpair_clos *) cl;
	if (clos->lp == NULL) {
		clos->lp = calloc(1, sizeof(*clos->lp));
		if (clos->lp == NULL)
			return (nmsg_res_memfail);
		clos->lp->base.descriptor = &nmsg__isc__linkpair__descriptor;
	}
	lp = clos->lp;

	if (pbuf != NULL && sz != NULL)
		return (finalize_pbuf(clos, pbuf, sz));

	if (strcmp(field, "type") == 0) {
		if (strcmp((char *) val, "anchor") == 0)
			lp->type = NMSG__ISC__LINKTYPE__anchor;
		else if (strcmp((char *) val, "redirect") == 0)
			lp->type = NMSG__ISC__LINKTYPE__redirect;
	} else if (strcmp(field, "src") == 0) {
		lp->src.data = malloc(len);
		if (lp->src.data == NULL)
			return (nmsg_res_memfail);
		memcpy(lp->src.data, val, len);
		lp->src.len = len;
	} else if (strcmp(field, "dst") == 0) {
		lp->dst.data = malloc(len);
		if (lp->dst.data == NULL)
			return (nmsg_res_memfail);
		memcpy(lp->dst.data, val, len);
		lp->dst.len = len;
	} else if (strcmp(field, "headers") == 0) {
		lp->headers.data = malloc(len);
		if (lp->headers.data == NULL)
			return (nmsg_res_memfail);
		memcpy(lp->headers.data, val, len);
		lp->headers.len = len;
		lp->has_headers = true;
	}

	return (nmsg_res_success);
}

/* Private. */

static nmsg_res
finalize_pbuf(struct linkpair_clos *clos, uint8_t **pbuf, size_t *sz) {
	clos->size += clos->lp->src.len;
	clos->size += clos->lp->dst.len;
	*pbuf = malloc(2 * clos->size);
	if (*pbuf == NULL) {
		reset_lp(clos);
		return (nmsg_res_memfail);
	}
	if (clos->lp->src.data == NULL || clos->lp->dst.data == NULL) {
		fprintf(stderr, "ERROR: linkpair: missing field\n");
		reset_lp(clos);
		return (nmsg_res_failure);
	}
	if (clos->lp->has_headers == true && clos->lp->headers.data == NULL) {
		clos->lp->headers.data = (uint8_t *) clos->headers;
		clos->lp->headers.len = strlen(clos->headers) + 1;
	}
	*sz = nmsg__isc__linkpair__pack(clos->lp, *pbuf);
	reset_lp(clos);
	return (nmsg_res_pbuf_ready);
}

static void
reset_lp(struct linkpair_clos *clos) {
	free(clos->lp->src.data);
	free(clos->lp->dst.data);
	if (clos->lp->headers.data != NULL &&
	    (void *) clos->lp->headers.data != (void *) clos->headers)
	{
		free(clos->lp->headers.data);
	}
	free(clos->lp);
	clos->lp = NULL;
	if (clos->headers_size > DEFAULT_HDRSZ)
		clos->headers = realloc(clos->headers, DEFAULT_HDRSZ);
	clos->headers_cur = clos->headers;
	clos->size = 0;
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
