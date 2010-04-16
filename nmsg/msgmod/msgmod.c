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
	switch (mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_module_init(mod, clos));
	case nmsg_msgmod_type_opaque:
		if (mod->plugin->init != NULL)
			return (mod->plugin->init(clos));
		else
			return (nmsg_res_success);
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_fini(struct nmsg_msgmod *mod, void **clos) {
	switch (mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_module_fini(mod, clos));
	case nmsg_msgmod_type_opaque:
		if (mod->plugin->fini != NULL)
			return (mod->plugin->fini(clos));
		else
			return (nmsg_res_success);
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_pres_to_payload(struct nmsg_msgmod *mod, void *clos, const char *pres) {
	switch (mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_pres_to_payload(mod, clos, pres));
	case nmsg_msgmod_type_opaque:
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_pres_to_payload_finalize(struct nmsg_msgmod *mod, void *clos,
				     uint8_t **pbuf, size_t *sz)
{
	switch (mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_msgmod_pres_to_payload_finalize(mod, clos, pbuf, sz));
	case nmsg_msgmod_type_opaque:
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_msgmod_ipdg_to_payload(struct nmsg_msgmod *mod, void *clos,
			    const struct nmsg_ipdg *dg,
			    uint8_t **pbuf, size_t *sz)
{
	if (mod->plugin->ipdg_to_payload != NULL)
		return (mod->plugin->ipdg_to_payload(clos, dg, pbuf, sz));
	else
		return (nmsg_res_notimpl);
}

nmsg_res
nmsg_msgmod_pkt_to_payload(struct nmsg_msgmod *mod, void *clos,
			   nmsg_pcap_t pcap, nmsg_message_t *m)
{
	if (mod->plugin->pkt_to_payload != NULL)
		return (mod->plugin->pkt_to_payload(clos, pcap, m));
	else
		return (nmsg_res_notimpl);
}

/* Internal use. */

struct nmsg_msgmod *
_nmsg_msgmod_start(struct nmsg_msgmod_plugin *plugin) {
	struct nmsg_msgmod *mod;
	nmsg_res res;

	mod = calloc(1, sizeof(*mod));
	if (mod == NULL)
		return (NULL);
	mod->plugin = plugin;

	switch (plugin->type) {
	case nmsg_msgmod_type_transparent:
		/* check transparent module API constraints */
		if (plugin->init != NULL ||
		    plugin->fini != NULL ||
		    plugin->pbdescr == NULL ||
		    plugin->fields == NULL)
		{
			goto err;
		}

		/* lookup field descriptors if necessary */
		if (plugin->fields[0].descr == NULL) {
			res = _nmsg_msgmod_load_field_descriptors(mod);
			if (res != nmsg_res_success) {
				goto err;
			}
		}
		break;

	case nmsg_msgmod_type_opaque:
		/* check opaque module API constraints */

		break;

	default:
		goto err;
	}

	/* check API constraints */
	if (plugin->vendor.id == 0 || plugin->msgtype.id == 0) {
		goto err;
	}

	return (mod);
err:
	free(mod);
	return (NULL);
}

void
_nmsg_msgmod_stop(struct nmsg_msgmod **mod) {
	free((*mod)->fields);
	free(*mod);
	*mod = NULL;
}
