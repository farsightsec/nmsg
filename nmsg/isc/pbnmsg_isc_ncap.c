/* pbnmsg_isc_ncap.c - ncap protobuf nmsg module */

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

#include <stdio.h>
#include <stdlib.h>

#include <nmsg.h>
#include <nmsg/ipdg.h>
#include <nmsg/pbmod.h>

#include "pbnmsg_isc_ncap.h"
#include "ncap.pb-c.c"

/* Data structures. */

struct ncap_clos {
	int	debug;
};

/* Exported via module context. */

static nmsg_res ncap_init(void **clos, int debug);
static nmsg_res ncap_fini(void **clos);
static nmsg_res ncap_pbuf_to_pres(Nmsg__NmsgPayload *np, char **pres,
				  const char *el);
static nmsg_res ncap_ipdg_to_pbuf(void *clos, const struct nmsg_ipdg *dg,
				  uint8_t **pbuf, size_t *sz);

/* Export. */

struct nmsg_pbmod nmsg_pbmod_ctx = {
	.pbmver = NMSG_PBMOD_VERSION,
	.vendor = NMSG_VENDOR_ISC,
	.msgtype = {
		{ MSGTYPE_NCAP_ID, MSGTYPE_NCAP_NAME },
		NMSG_IDNAME_END
	},
	.init = ncap_init,
	.fini = ncap_fini,
	.pbuf_to_pres = ncap_pbuf_to_pres,
	.ipdg_to_pbuf = ncap_ipdg_to_pbuf
};

/* Private. */

static nmsg_res
ncap_init(void **clos, int debug) {
	struct ncap_clos *nclos;

	nclos = *clos = calloc(1, sizeof(*nclos));
	if (nclos == NULL)
		return (nmsg_res_memfail);
	nclos->debug = debug;

	return (nmsg_res_success);
}

static nmsg_res
ncap_fini(void **clos) {
	free(*clos);
	*clos = NULL;
	return (nmsg_res_success);
}

static nmsg_res
ncap_pbuf_to_pres(Nmsg__NmsgPayload *np __attribute__((unused)),
		  char **pres __attribute__((unused)),
		  const char *el __attribute__((unused)))
{
	return (nmsg_res_success);
}

static nmsg_res
ncap_ipdg_to_pbuf(void *clos, const struct nmsg_ipdg *dg,
		  uint8_t **pbuf, size_t *sz)
{
	struct ncap_clos *nclos = (struct ncap_clos *) clos;

	fprintf(stderr, "%s: nclos=%p dg=%p pbuf=%p sz=%p\n",
		__func__, nclos, dg, pbuf, sz);

	return (nmsg_res_success);
}
