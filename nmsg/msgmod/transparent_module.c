/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2009, 2010, 2012 by Farsight Security, Inc.
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

nmsg_res
_nmsg_msgmod_module_init(struct nmsg_msgmod *mod, void **cl) {
	size_t n;
	struct nmsg_msgmod_clos **clos = (struct nmsg_msgmod_clos **) cl;
	struct nmsg_msgmod_field *field;
	unsigned max_fieldid = 0;

	/* allocate the closure */
	*clos = calloc(1, sizeof(struct nmsg_msgmod_clos));
	if (*clos == NULL) {
		return (nmsg_res_memfail);
	}

	/* find the maximum field id */
	for (n = 0; n < mod->n_fields; n++) {
		field = &mod->fields[n];
		if (field->descr != NULL && field->descr->id > max_fieldid)
			max_fieldid = field->descr->id;
	}

	/* (probably) shouldn't happen. */
	if (max_fieldid <= 1)
		return (nmsg_res_failure);

	/* allocate space for pointers to multiline buffers */
	(*clos)->strbufs = calloc(1, (sizeof(struct nmsg_strbuf_storage)) *
				  max_fieldid - 1);
	if ((*clos)->strbufs == NULL) {
		free(*clos);
		return (nmsg_res_memfail);
	}

	for(size_t ndx=0;ndx<max_fieldid;++ndx) {
		_nmsg_strbuf_init(&((struct nmsg_strbuf_storage *) (*clos)->strbufs)[ndx]);
	}

	/* call module-specific init function */
	if (mod->plugin->init != NULL)
		return (mod->plugin->init(&(*clos)->mod_clos));
	else
		return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_module_fini(struct nmsg_msgmod *mod, void **cl) {
	nmsg_res res;
	size_t n;
	struct nmsg_msgmod_clos **clos = (struct nmsg_msgmod_clos **) cl;
	struct nmsg_msgmod_field *field;

	res = nmsg_res_success;

	/* deallocate serialized message buffer */
	free((*clos)->nmsg_pbuf);

	/* deallocate multiline buffers */
	for (n = 0; n < mod->n_fields; n++) {
		field = &mod->fields[n];
		if (field->type == nmsg_msgmod_ft_mlstring) {
			struct nmsg_strbuf *sb;

			sb = &((*clos)->strbufs[field->descr->id - 1]);
			_nmsg_strbuf_destroy((struct nmsg_strbuf_storage *) sb);
		}
	}

	/* deallocate multiline buffer pointers */
	free((*clos)->strbufs);

	/* call module-specific fini function */
	if (mod->plugin->fini != NULL)
		res = mod->plugin->fini(&(*clos)->mod_clos);

	/* deallocate closure */
	free(*clos);
	*clos = NULL;

	return (res);
}
