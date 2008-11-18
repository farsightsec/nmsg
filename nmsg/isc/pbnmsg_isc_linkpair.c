/* pbnmsg_isc_linkpair.c - link pair protobuf nmsg module */

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

#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>
#include <nmsg/pbmod.h>

#include "linkpair.pb-c.h"

/* Data structures. */

struct linkpair_clos {
	Nmsg__Isc__Linkpair	*lp;
	bool			hdrblock;
	size_t			max;
	ssize_t			rem;
};

/* Forward. */

static nmsg_res finalize_pbuf(struct linkpair_clos *, uint8_t **pbuf,
			      size_t *);
static size_t trim_newline(char *);
static void destroy_lp(struct linkpair_clos *);
static bool rem_avail(ssize_t rem, size_t len);

/* Exported via module context. */

static void *linkpair_init(size_t max, int debug);
static nmsg_res linkpair_fini(void *);
static nmsg_res linkpair_pbuf_to_pres(Nmsg__NmsgPayload *, char **pres,
				      const char *endline);
static nmsg_res linkpair_pres_to_pbuf(void *, const char *line,
				      uint8_t **pbuf, size_t *);
static void linkpair_free_pbuf(uint8_t **);
static void linkpair_free_pres(void *, char **);

/* Export. */

#define MSGTYPE_LINKPAIR_ID	3
#define MSGTYPE_LINKPAIR_NAME	"linkpair"

#define PAYLOAD_MAXSZ		1208

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.init = &linkpair_init,
	.fini = &linkpair_fini,
	.pbuf2pres = &linkpair_pbuf_to_pres,
	.pres2pbuf = &linkpair_pres_to_pbuf,
	.free_pbuf = &linkpair_free_pbuf,
	.free_pres = &linkpair_free_pres,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_LINKPAIR_ID, MSGTYPE_LINKPAIR_NAME },
		NMSG_IDNAME_END
	}
};

/* Exported via module context. */

static void *
linkpair_init(size_t max, int debug) {
	struct linkpair_clos *clos;

	if (debug > 2)
		fprintf(stderr, "linkpair: starting module\n");
	clos = calloc(1, sizeof(*clos));
	if (clos == NULL)
		return (NULL);
	clos->max = (max > PAYLOAD_MAXSZ) ? PAYLOAD_MAXSZ : max;
	clos->rem = clos->max;
	return (clos);
}

static nmsg_res
linkpair_fini(void *clos) {
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
		clos->lp->base.descriptor = &nmsg__isc__linkpair__descriptor;
	}

	if (clos->hdrblock == true) {
		if (strncmp(line, ".\n", 2) == 0)
			clos->hdrblock = false;
		else {
			unsigned char *dst;
			size_t len;

			len = strlen(line);
			if (rem_avail(clos->rem, len) == false) {
				clos->lp->truncated = true;
				return (nmsg_res_success);
			}
			if (clos->lp->headers.data == NULL) {
				clos->lp->has_headers = true;
				clos->lp->headers.data = calloc(1,
								PAYLOAD_MAXSZ);
				if (clos->lp->headers.data == NULL)
					return (nmsg_res_memfail);
			}
			dst = clos->lp->headers.data;
			dst += clos->lp->headers.len;
			strcpy((char *) dst, line);
			clos->lp->headers.len += len;
			clos->rem -= len;
		}
	} else {
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

				if (rem_avail(clos->rem, len) == false)
					return (nmsg_res_success);

				clos->lp->src.data = (uint8_t *) copy;
				clos->lp->src.len = len + 1;
				clos->rem -= clos->lp->src.len;
			}
		} else if (strncmp(line, "dst: ", sizeof("dst: ") - 1) == 0) {
			const char *sdst = line + sizeof("dst: ") - 1;

			if (clos->lp->dst.data == NULL) {
				char *copy = strdup(sdst);
				size_t len = trim_newline(copy);

				if (rem_avail(clos->rem, len) == false)
					return (nmsg_res_success);

				clos->lp->dst.data = (uint8_t *) copy;
				clos->lp->dst.len = len + 1;
				clos->rem -= clos->lp->dst.len;
			}
		} else if (strncmp(line, "headers:",
				   sizeof("headers:") - 1) == 0)
		{
			clos->hdrblock = true;
			clos->lp->has_headers = true;
		} else if (line[0] == '\n') {
			return (finalize_pbuf(clos, pbuf, sz));
		}
	}

	return (nmsg_res_success);
}

static nmsg_res
linkpair_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Linkpair *linkpair;
	const char *headers;
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
	if (linkpair->truncated == true)
		headers = "headers: [truncated]\n";
	else
		headers = "headers:\n";

	asprintf(pres, "type: %s%ssrc: %s%sdst: %s%s%s%s%s\n",
		 linktype, el, linkpair->src.data, el, linkpair->dst.data, el,
		 linkpair->has_headers ? headers : "",
		 linkpair->has_headers ? (char *) linkpair->headers.data : "",
		 linkpair->has_headers ? ".\n" : "");
	nmsg__isc__linkpair__free_unpacked(linkpair, NULL);
	return (nmsg_res_success);
}

static void
linkpair_free_pbuf(uint8_t **pbuf) {
	free(*pbuf);
	*pbuf = NULL;
}

static void
linkpair_free_pres(void *cl __attribute__((unused)), char **pres) {
	free(*pres);
	*pres = NULL;
}

/* Private. */

static nmsg_res
finalize_pbuf(struct linkpair_clos *clos, uint8_t **pbuf, size_t *sz) {
	if (clos->lp->src.data == NULL || clos->lp->dst.data == NULL) {
		fprintf(stderr, "ERROR: linkpair: missing field\n");
		destroy_lp(clos);
		return (nmsg_res_failure);
	}
	clos->lp->headers.len += 1;

	*pbuf = malloc(2 * clos->max);
	if (*pbuf == NULL)
		return (nmsg_res_memfail);
	*sz = nmsg__isc__linkpair__pack(clos->lp, *pbuf);
	destroy_lp(clos);
	return (nmsg_res_pbuf_ready);
}

static void
destroy_lp(struct linkpair_clos *clos) {
	free(clos->lp->src.data);
	free(clos->lp->dst.data);
	free(clos->lp->headers.data);
	free(clos->lp);
	clos->lp = NULL;
	clos->rem = clos->max;
}

static bool
rem_avail(ssize_t rem, size_t len) {
	if (rem - (ssize_t) len > 0)
		return (true);
	return (false);
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
