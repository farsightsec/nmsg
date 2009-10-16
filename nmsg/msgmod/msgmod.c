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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nmsg.h"
#include "private.h"

#include "transparent.h"

/* Export. */

nmsg_res
nmsg_msgmod_init(struct nmsg_msgmod *mod, void **clos) {
	switch (mod->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_module_init(mod, clos));
	case nmsg_msgmod_type_opaque:
		if (mod->init != NULL)
			return (mod->init(clos));
		else
			return (nmsg_res_success);
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_fini(struct nmsg_msgmod *mod, void **clos) {
	switch (mod->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_module_fini(mod, clos));
	case nmsg_msgmod_type_opaque:
		if (mod->fini != NULL)
			return (mod->fini(clos));
		else
			return (nmsg_res_success);
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_payload_to_pres(struct nmsg_msgmod *mod, Nmsg__NmsgPayload *np,
			    char **pres, const char *endline)
{
	switch (mod->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_payload_to_pres(mod, np, pres, endline));
	case nmsg_msgmod_type_opaque:
		if (mod->payload_to_pres != NULL)
			return (mod->payload_to_pres(np, pres, endline));
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_pres_to_payload(struct nmsg_msgmod *mod, void *clos, const char *pres) {
	switch (mod->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_pres_to_payload(mod, clos, pres));
	case nmsg_msgmod_type_opaque:
		if (mod->pres_to_payload != NULL)
			return (mod->pres_to_payload(clos, pres));
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_pres_to_payload_finalize(struct nmsg_msgmod *mod, void *clos,
				     uint8_t **pbuf, size_t *sz)
{
	switch (mod->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_pres_to_payload_finalize(mod, clos, pbuf, sz));
	case nmsg_msgmod_type_opaque:
		if (mod->pres_to_payload_finalize != NULL)
			return (mod->pres_to_payload_finalize(clos, pbuf, sz));
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_ipdg_to_payload(struct nmsg_msgmod *mod, void *clos,
			    const struct nmsg_ipdg *dg,
			    uint8_t **pbuf, size_t *sz)
{
	if (mod->ipdg_to_payload != NULL)
		return (mod->ipdg_to_payload(clos, dg, pbuf, sz));
	else
		return (nmsg_res_notimpl);
}

/* Internal use. */

nmsg_res
_nmsg_msgmod_start(struct nmsg_msgmod *mod) {
	nmsg_res res;

	switch (mod->type) {
	case nmsg_msgmod_type_transparent:
		/* check transparent module API constraints */
		if (mod->init != NULL ||
		    mod->fini != NULL ||
		    mod->pbdescr == NULL ||
		    mod->fields == NULL)
		{
			return (nmsg_res_failure);
		}

		/* lookup field descriptors if necessary */
		if (mod->fields[0].descr == NULL) {
			res = _nmsg_msgmod_load_field_descriptors(mod);
			if (res != nmsg_res_success)
				return (res);
		}
		break;

	case nmsg_msgmod_type_opaque:
		/* check opaque module API constraints */

		break;

	default:
		return (nmsg_res_failure);
	}

	/* check API constraints */
	if (mod->vendor.id == 0 ||
	    mod->msgtype.id == 0 ||
	    (mod->pres_to_payload != NULL &&
	     mod->pres_to_payload_finalize == NULL) ||
	    (mod->pres_to_payload == NULL &&
	     mod->pres_to_payload_finalize != NULL))
	{
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}
