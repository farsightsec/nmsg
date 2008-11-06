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

#include "nmsg.h"
#include "private.h"
#include "nmsg/pbmod.h"

/* Export. */

nmsg_res
nmsg_pbmod_pbuf2pres(struct nmsg_pbmod *mod, Nmsg__NmsgPayload *np,
		     char **pres, const char *endline)
{
	if (mod->pbuf2pres != NULL)
		return (mod->pbuf2pres(np, pres, endline));
	else
		return (nmsg_res_notimpl);
}

nmsg_res
nmsg_pbmod_pres2pbuf(struct nmsg_pbmod *mod, void *clos, const char *pres,
		     uint8_t **pbuf, size_t *sz)
{
	if (mod->pres2pbuf != NULL)
		return (mod->pres2pbuf(clos, pres, pbuf, sz));
	else
		return (nmsg_res_notimpl);
}

nmsg_res
nmsg_pbmod_free_pbuf(struct nmsg_pbmod *mod, uint8_t *pbuf) {
	if (mod->free_pbuf != NULL)
		return (mod->free_pbuf(pbuf));
	else
		return (nmsg_res_notimpl);
}

nmsg_res
nmsg_pbmod_free_pres(struct nmsg_pbmod *mod, char **pres) {
	if (mod->free_pres != NULL)
		return (mod->free_pres(pres));
	else
		return (nmsg_res_notimpl);
}
