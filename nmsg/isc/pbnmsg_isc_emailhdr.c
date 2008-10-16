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

#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>

#include "emailhdr.pb-c.h"

/* Forward. */

static nmsg_res emailhdr_init(int debug);
static nmsg_res emailhdr_fini(void);
static nmsg_res emailhdr_pbuf_to_pres(Nmsg__NmsgPayload *, char **pres,
				      const char *endline);
static nmsg_res emailhdr_pres_to_pbuf(const char *line, uint8_t **pbuf,
				      size_t *sz);
static nmsg_res emailhdr_free_pbuf(uint8_t *);
static nmsg_res emailhdr_free_pres(char **);
static nmsg_res finalize_pbuf(uint8_t **pbuf, size_t *sz, bool trunc);

/* Macros. */

#define HDRSIZE_MAX	2048

/* Data. */

static struct {
	char *pres;
	char *pres_cur;
	bool body;
} clos;

/* Export. */

#define MSGTYPE_EMAILHDR_ID	2
#define MSGTYPE_EMAILHDR_NAME	"emailhdr"

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.init = &emailhdr_init,
	.fini = &emailhdr_fini,
	.pbuf2pres = &emailhdr_pbuf_to_pres,
	.pres2pbuf = &emailhdr_pres_to_pbuf,
	.free_pbuf = &emailhdr_free_pbuf,
	.free_pres = &emailhdr_free_pres,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_EMAILHDR_ID, MSGTYPE_EMAILHDR_NAME },
		NMSG_IDNAME_END
	}
};

/* Exported via module context. */

static nmsg_res
emailhdr_init(int debug) {
	if (debug > 2)
		fprintf(stderr, "emailhdr: starting module\n");
	clos.pres_cur = clos.pres = calloc(1, HDRSIZE_MAX);
	if (clos.pres == NULL)
		return (nmsg_res_memfail);
	return (nmsg_res_success);
}

static nmsg_res
emailhdr_fini(void) {
	free(clos.pres);
	return (nmsg_res_success);
}

static nmsg_res
emailhdr_pres_to_pbuf(const char *line, uint8_t **pbuf, size_t *sz) {
	size_t len;

	len = strlen(line);
	if (len >= 5 &&
	    line[0] == 'F' &&
	    line[1] == 'r' &&
	    line[2] == 'o' &&
	    line[3] == 'm' &&
	    line[4] == ' ')
	{
		/* new message */
		clos.body = false;
		clos.pres_cur = clos.pres;
	}
	if (line[0] == '\n' && clos.body == false) {
		/* all headers read in, emit a pbuf */
		clos.body = true;
		return (finalize_pbuf(pbuf, sz, false));
	}
	if (clos.body) {
		/* body line, ignore */
		return (nmsg_res_success);
	}
	if (clos.pres_cur - clos.pres + len + 1 > HDRSIZE_MAX) {
		/* add'l header line would be too large, emit truncated */
		return (finalize_pbuf(pbuf, sz, true));
	} else {
		/* append header line to buffer */
		strncpy(clos.pres_cur, line, len);
		clos.pres_cur[len] = '\0';
		clos.pres_cur += len;
	}
	return (nmsg_res_success);
}

static nmsg_res
emailhdr_free_pbuf(uint8_t *pbuf) {
	free(pbuf);
	return (nmsg_res_success);
}

static nmsg_res
emailhdr_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres, const char *el) {
	Nmsg__Isc__Emailhdr *emailhdr;

	if (np->vid != NMSG_VENDOR_ISC_ID &&
	    np->msgtype != MSGTYPE_EMAILHDR_ID)
		return (nmsg_res_module_mismatch);
	if (np->has_payload == 0)
		return (nmsg_res_no_payload);
	emailhdr = nmsg__isc__emailhdr__unpack(NULL, np->payload.len,
					       np->payload.data);
	asprintf(pres, "truncated=%d %s%s\n", emailhdr->truncated, el,
		 emailhdr->headers.data);
	nmsg__isc__emailhdr__free_unpacked(emailhdr, NULL);

	return (nmsg_res_success);
}

static nmsg_res
emailhdr_free_pres(char **pres) {
	free(*pres);
	*pres = NULL;
	return (nmsg_res_success);
}

/* Private. */

static nmsg_res
finalize_pbuf(uint8_t **pbuf, size_t *sz, bool trunc) {
	Nmsg__Isc__Emailhdr *emailhdr;

	*pbuf = malloc(2 * HDRSIZE_MAX);
	if (*pbuf == NULL)
		return (nmsg_res_memfail);
	emailhdr = alloca(sizeof(*emailhdr));
	if (emailhdr == NULL)
		return (nmsg_res_memfail);
	memset(emailhdr, 0, sizeof(*emailhdr));
	emailhdr->base.descriptor = &nmsg__isc__emailhdr__descriptor;
	emailhdr->truncated = trunc;
	emailhdr->headers.len = strnlen(clos.pres, HDRSIZE_MAX) + 1;
	emailhdr->headers.data = (uint8_t *) clos.pres;
	*sz = nmsg__isc__emailhdr__pack(emailhdr, *pbuf);

	return (nmsg_res_pbuf_ready);
}
