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
_nmsg_msgmod_message_reset(struct nmsg_msgmod *mod, void *m) {
	ProtobufCBinaryData *bdata;
	struct nmsg_msgmod_field *field;

	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->descr->type == PROTOBUF_C_TYPE_BYTES) {
			if (PBFIELD_REPEATED(field)) {
				ProtobufCBinaryData **arr_bdata;
				size_t i, n;

				n = *PBFIELD_Q(m, field);
				if (n > 0) {
					arr_bdata = PBFIELD(m, field,
							    ProtobufCBinaryData *);
					for (i = 0; i < n; i++) {
						bdata = &(*arr_bdata)[i];
						if (bdata->data != NULL) {
							free(bdata->data);
							bdata->data = NULL;
							bdata->len = 0;
						}
					}
					free(*arr_bdata);
					*arr_bdata = NULL;
				}
			} else {
				bdata = PBFIELD(m, field, ProtobufCBinaryData);
				if (bdata->data != NULL) {
					free(bdata->data);
					bdata->data = NULL;
					bdata->len = 0;
				}
			}
		}
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL ||
		    field->descr->label == PROTOBUF_C_LABEL_REPEATED)
			*PBFIELD_Q(m, field) = 0;
	}
	return (nmsg_res_success);
}
