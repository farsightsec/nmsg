/*
 * Copyright (c) 2009, 2010, 2012, 2015 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "private.h"

#include "transparent.h"

static int
_nmsg_msgmod_field_cmp(const void *v1, const void *v2)
{
	const struct nmsg_msgmod_field **f1 = (const struct nmsg_msgmod_field **) v1;
	const struct nmsg_msgmod_field **f2 = (const struct nmsg_msgmod_field **) v2;

	return (strcmp((*f1)->name, (*f2)->name));
}

struct nmsg_msgmod_field *
_nmsg_msgmod_lookup_field(struct nmsg_msgmod *mod, const char *name) {
	struct nmsg_msgmod_field **res;
	struct nmsg_msgmod_field key;
	struct nmsg_msgmod_field *key_ptr;

	key.name = name;
	key_ptr = &key;

	res = bsearch(&key_ptr,
		      &mod->fields_idx[0],
		      mod->n_fields,
		      sizeof(struct nmsg_msgmod_field *),
		      _nmsg_msgmod_field_cmp);

	if (res) {
		return (*res);
	} else {
		return NULL;
	}
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
			_nmsg_dprintf(1, "%s: no pbfield or field getter found for "
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
	mod->fields_idx = calloc(1, sizeof(struct nmsg_msgmod_field *) * (mod->n_fields + 1));
	if (mod->fields_idx == NULL) {
		free(mod->fields);
		return (nmsg_res_memfail);
	}

	for(i = 0; i < mod->n_fields; i++) {
		mod->fields_idx[i] = &mod->fields[i];
	}
	qsort(&mod->fields_idx[0],
	      mod->n_fields,
	      sizeof(struct nmsg_msgmod_field *),
	      _nmsg_msgmod_field_cmp);

	return (nmsg_res_success);
}
