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

#include <stdlib.h>

#include "nmsg.h"
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

	/* allocate space for pointers to multiline buffers */
	(*clos)->strbufs = calloc(1, (sizeof(struct nmsg_strbuf)) *
				  max_fieldid - 1);
	if ((*clos)->strbufs == NULL) {
		free(*clos);
		return (nmsg_res_memfail);
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
			free(sb->data);
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
