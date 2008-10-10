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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>

#include "emailhdr.pb-c.h"

/* Forward. */

static nmsg_res emailhdr_init(int debug);
static nmsg_res emailhdr_fini(void);
static nmsg_res emailhdr_pres_to_pbuf(const char *line, uint8_t **pbuf, size_t *sz);
static nmsg_res emailhdr_free_pbuf(uint8_t *);

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

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.init = &emailhdr_init,
	.fini = &emailhdr_fini,
	.pres2pbuf = &emailhdr_pres_to_pbuf,
	.free_pbuf = &emailhdr_free_pbuf,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ 2, "emailhdr" },
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

	if (line[0] == 'F' &&
	    line[1] == 'r' &&
	    line[2] == 'o' &&
	    line[3] == 'm' &&
	    line[4] == ' ')
	{
		clos.body = false;
		clos.pres_cur = clos.pres;
	}
	
	if (line[0] == '\n') {
		if (!clos.body) {
			clos.body = true;
			return (finalize_pbuf(pbuf, sz, false));
		}
	}

	if (clos.body) {
		return (nmsg_res_success);
	}

	len = strlen(line);
	if (clos.pres_cur - clos.pres + len > HDRSIZE_MAX) {
		return (finalize_pbuf(pbuf, sz, true));
	} else {
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

/* Private. */

static nmsg_res
finalize_pbuf(uint8_t **pbuf, size_t *sz, bool trunc) {
	Nmsg__Isc__Emailhdr *emailhdr;

	*pbuf = malloc(2 * HDRSIZE_MAX);
	if (*pbuf == NULL)
		return (nmsg_res_memfail);
	emailhdr = alloca(sizeof *emailhdr);
	if (emailhdr == NULL)
		return (nmsg_res_memfail);
	emailhdr->base.descriptor = &nmsg__isc__emailhdr__descriptor;
	emailhdr->truncated = trunc;
	emailhdr->headers.len = strnlen(clos.pres, HDRSIZE_MAX);
	emailhdr->headers.data = (uint8_t *) clos.pres;
	*sz = nmsg__isc__emailhdr__pack(emailhdr, *pbuf);

	return (nmsg_res_pbuf_ready);
}
