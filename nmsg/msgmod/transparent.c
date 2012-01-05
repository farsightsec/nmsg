/*
 * Copyright (c) 2009, 2010, 2012 by Internet Systems Consortium, Inc. ("ISC")
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

#include "private.h"

#include "transparent.h"

static int
_nmsg_msgmod_field_cmp(const void *v1, const void *v2)
{
	const struct nmsg_msgmod_field *f1 = (const struct nmsg_msgmod_field *) v1;
	const struct nmsg_msgmod_field *f2 = (const struct nmsg_msgmod_field *) v2;

	return (strcmp(f1->name, f2->name));
}

struct nmsg_msgmod_field *
_nmsg_msgmod_lookup_field(struct nmsg_msgmod *mod, const char *name) {
	struct nmsg_msgmod_field *res;
	struct nmsg_msgmod_field key;

	key.name = name;

	res = bsearch(&key,
		      &mod->fields[0],
		      mod->n_fields,
		      sizeof(struct nmsg_msgmod_field),
		      _nmsg_msgmod_field_cmp);

	return (res);
}

nmsg_res
_nmsg_msgmod_load_field_descriptors(struct nmsg_msgmod *mod) {
	const ProtobufCFieldDescriptor *pbfield;
	struct nmsg_msgmod_field *field, *plugin_field;
	unsigned i;

	/* lookup the field descriptors by name */
	for (plugin_field = &mod->plugin->fields[0];
	     plugin_field->name != NULL;
	     plugin_field++)
	{
		bool descr_found = false;

		for (i = 0; i < mod->plugin->pbdescr->n_fields; i++) {
			pbfield = &mod->plugin->pbdescr->fields[i];
			if (strcmp(pbfield->name, plugin_field->name) == 0) {
				descr_found = true;
				plugin_field->descr = pbfield;
				break;
			}
		}
		if (descr_found == false && plugin_field->get == NULL) {
			if (_nmsg_global_debug >= 1)
				fprintf(stderr, "%s: no pbfield or field getter found for "
					"field '%s'\n", __func__, plugin_field->name);
			return (nmsg_res_failure);
		}
	}

	/* count number of plugin fields */
	mod->n_fields = 0;
	for (field = &mod->plugin->fields[0];
	     field->name != NULL;
	     field++)
	{
		mod->n_fields += 1;
	}

	/* create nmsg_msgmod_field table from plugin's fields */
	mod->fields = calloc(1, sizeof(struct nmsg_msgmod_field) * (mod->n_fields + 1));
	if (mod->fields == NULL)
		return (nmsg_res_memfail);

	for (field = &mod->fields[0], plugin_field = &mod->plugin->fields[0];
	     plugin_field->name != NULL;
	     field++, plugin_field++)
	{
		memcpy(field, plugin_field, sizeof(struct nmsg_msgmod_field));
	}

	/* sort field descriptors by name */
	qsort(&mod->fields[0],
	      mod->n_fields,
	      sizeof(struct nmsg_msgmod_field),
	      _nmsg_msgmod_field_cmp);

	return (nmsg_res_success);
}
