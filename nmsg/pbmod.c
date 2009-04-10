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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nmsg.h"
#include "private.h"

/* Macros. */

#define PBFIELD(pbuf, field, type) \
	((type *) &((char *) pbuf)[field->descr->offset])

#define PBFIELD_Q(pbuf, field) \
	((int *) &((char *) pbuf)[field->descr->quantifier_offset])

#define PBFIELD_ONE_PRESENT(pbuf, field) \
	(field->descr->label == PROTOBUF_C_LABEL_REQUIRED || \
	 (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL && \
	  *PBFIELD_Q(pbuf, field) == 1))

#define PBFIELD_REPEATED(field) \
	(field->descr->label == PROTOBUF_C_LABEL_REPEATED)

#define LINECMP(line, str) (strncmp(line, str, sizeof(str) - 1) == 0)

/* Forward. */

static bool is_automatic_pbmod(struct nmsg_pbmod *mod);
static inline size_t sizeof_elt_in_repeated_array (ProtobufCType type);
static nmsg_res module_fini(struct nmsg_pbmod *mod, void **clos);
static nmsg_res module_init(struct nmsg_pbmod *mod, void **clos);
static void load_field_descriptors(struct nmsg_pbmod *mod);


/* pbmod_pbuf.c */
static nmsg_res pbuf_to_pres(struct nmsg_pbmod *mod, Nmsg__NmsgPayload *np,
			     char **pres, const char *endline);
static nmsg_res pbuf_to_pres_load(struct nmsg_pbmod_field *field, void *ptr,
				  struct nmsg_strbuf *sb, const char *endline);

/* pbmod_pres.c */
static nmsg_res pres_to_pbuf(struct nmsg_pbmod *mod, void *clos,
			     const char *pres);
static nmsg_res pres_to_pbuf_load(struct nmsg_pbmod_field *field,
				  struct nmsg_pbmod_clos *clos,
				  const char *value, void *ptr, int *qptr);
static nmsg_res pres_to_pbuf_finalize(struct nmsg_pbmod *mod, void *clos,
				      uint8_t **pbuf, size_t *sz);
/* Export. */

nmsg_res
nmsg_pbmod_init(struct nmsg_pbmod *mod, void **clos, int debug) {
	if (is_automatic_pbmod(mod)) {
		return (module_init(mod, clos));
	} else if (mod->init != NULL) {
		return (mod->init(clos, debug));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_fini(struct nmsg_pbmod *mod, void **clos) {
	if (is_automatic_pbmod(mod)) {
		return (module_fini(mod, clos));
	} else if (mod->fini != NULL) {
		return (mod->fini(clos));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_pbuf_to_pres(struct nmsg_pbmod *mod, Nmsg__NmsgPayload *np,
			char **pres, const char *endline)
{
	if (is_automatic_pbmod(mod)) {
		return (pbuf_to_pres(mod, np, pres, endline));
	} else if (mod->pbuf_to_pres != NULL) {
		return (mod->pbuf_to_pres(np, pres, endline));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_pres_to_pbuf(struct nmsg_pbmod *mod, void *clos, const char *pres) {
	if (is_automatic_pbmod(mod)) {
		return (pres_to_pbuf(mod, clos, pres));
	} else if (mod->pres_to_pbuf != NULL) {
		return (mod->pres_to_pbuf(clos, pres));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_pres_to_pbuf_finalize(struct nmsg_pbmod *mod, void *clos,
				 uint8_t **pbuf, size_t *sz)
{
	if (is_automatic_pbmod(mod)) {
		return (pres_to_pbuf_finalize(mod, clos, pbuf, sz));
	} else if (mod->pres_to_pbuf_finalize != NULL) {
		return (mod->pres_to_pbuf_finalize(clos, pbuf, sz));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_ipdg_to_pbuf(struct nmsg_pbmod *mod, void *clos,
			const struct nmsg_ipdg *dg,
			uint8_t **pbuf, size_t *sz)
{
	if (mod->ipdg_to_pbuf != NULL)
		return (mod->ipdg_to_pbuf(clos, dg, pbuf, sz));
	else
		return (nmsg_res_notimpl);
}

nmsg_res
nmsg_pbmod_message_init(struct nmsg_pbmod *mod, void *m) {
	if (is_automatic_pbmod(mod)) {
		((ProtobufCMessage *) m)->descriptor = mod->pbdescr;
	} else {
		return (nmsg_res_notimpl);
	}
	return (nmsg_res_success);
}

nmsg_res
nmsg_pbmod_message_reset(struct nmsg_pbmod *mod, void *m) {
	ProtobufCBinaryData *bdata;
	struct nmsg_pbmod_field *field;

	if (!is_automatic_pbmod(mod))
		return (nmsg_res_notimpl);

	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->type == nmsg_pbmod_ft_ip ||
		    field->type == nmsg_pbmod_ft_string ||
		    field->type == nmsg_pbmod_ft_mlstring)
		{
			if (PBFIELD_ONE_PRESENT(m, field)) {
				bdata = PBFIELD(m, field, ProtobufCBinaryData);
				bdata->len = 0;
				if (bdata->data != NULL) {
					free(bdata->data);
					bdata->data = NULL;
				}
			} else if (PBFIELD_REPEATED(field)) {
				ProtobufCBinaryData **arr_bdata;
				size_t i, n;

				n = *PBFIELD_Q(m, field);
				if (n > 0) {
					arr_bdata = PBFIELD(m, field,
							ProtobufCBinaryData *);
					for (i = 0; i < n; i++) {
						bdata = &(*arr_bdata)[i];
						if (bdata->data != NULL)
							free(bdata->data);
					}
					free(*arr_bdata);
				}
			}
		}
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL ||
		    field->descr->label == PROTOBUF_C_LABEL_REPEATED)
			*PBFIELD_Q(m, field) = 0;
	}
	return (nmsg_res_success);
}

/* Internal use. */

nmsg_res
_nmsg_pbmod_start(struct nmsg_pbmod *mod) {
	if (is_automatic_pbmod(mod)) {
		/* lookup field descriptors if necessary */
		if (mod->fields[0].descr == NULL)
			load_field_descriptors(mod);
	}

	return (nmsg_res_success);
}

/* Private. */

static nmsg_res
module_init(struct nmsg_pbmod *mod, void **cl) {
	struct nmsg_pbmod_clos **clos = (struct nmsg_pbmod_clos **) cl;
	struct nmsg_pbmod_field *field;
	unsigned max_fieldid = 0;

	/* allocate the closure */
	*clos = calloc(1, sizeof(struct nmsg_pbmod_clos));
	if (*clos == NULL) {
		return (nmsg_res_memfail);
	}

	/* find the maximum field id */
	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->descr->id > max_fieldid)
			max_fieldid = field->descr->id;
	}

	/* allocate space for pointers to multiline buffers */
	(*clos)->strbufs = calloc(1, (sizeof(struct nmsg_strbuf)) *
				  max_fieldid - 1);
	if ((*clos)->strbufs == NULL) {
		free(*clos);
		return (nmsg_res_memfail);
	}

	return (nmsg_res_success);
}

static nmsg_res
module_fini(struct nmsg_pbmod *mod, void **cl) {
	struct nmsg_pbmod_clos **clos = (struct nmsg_pbmod_clos **) cl;
	struct nmsg_pbmod_field *field;

	/* deallocate serialized message buffer */
	free((*clos)->nmsg_pbuf);

	/* deallocate multiline buffers */
	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->type == nmsg_pbmod_ft_mlstring) {
			struct nmsg_strbuf *sb;

			sb = &((*clos)->strbufs[field->descr->id - 1]);
			free(sb->data);
		}
	}

	/* deallocate multiline buffer pointers */
	free((*clos)->strbufs);

	/* deallocate closure */
	free(*clos);
	*clos = NULL;

	return (nmsg_res_success);
}

static void
load_field_descriptors(struct nmsg_pbmod *mod) {
	const ProtobufCFieldDescriptor *pbfield;
	struct nmsg_pbmod_field *field;
	unsigned i;

	/* lookup the field descriptors by name */
	for (field = mod->fields; field->name != NULL; field++) {
		bool descr_found = false;

		for (i = 0; i < mod->pbdescr->n_fields; i++) {
			pbfield = &mod->pbfields[i];
			if (strcmp(pbfield->name, field->name) == 0) {
				descr_found = true;
				field->descr = pbfield;
				break;
			}
		}
		assert(descr_found == true);
	}
}

static bool
is_automatic_pbmod(struct nmsg_pbmod *mod) {
	if (mod->init == NULL &&
	    mod->fini == NULL &&
	    mod->pbuf_to_pres == NULL &&
	    mod->pres_to_pbuf == NULL &&
	    mod->pres_to_pbuf_finalize == NULL &&
	    mod->pbdescr != NULL &&
	    mod->pbfields != NULL &&
	    mod->fields != NULL)
	{
		return (true);
	}
	return (false);
}

/* from protobuf-c.c */

static inline size_t sizeof_elt_in_repeated_array (ProtobufCType type)
{
  switch (type)
    {
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
    case PROTOBUF_C_TYPE_FIXED32:
    case PROTOBUF_C_TYPE_FLOAT:
    case PROTOBUF_C_TYPE_ENUM:
      return 4;
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
    case PROTOBUF_C_TYPE_FIXED64:
    case PROTOBUF_C_TYPE_DOUBLE:
      return 8;
    case PROTOBUF_C_TYPE_BOOL:
      return sizeof (protobuf_c_boolean);
    case PROTOBUF_C_TYPE_STRING:
    case PROTOBUF_C_TYPE_MESSAGE:
      return sizeof (void *);
    case PROTOBUF_C_TYPE_BYTES:
      return sizeof (ProtobufCBinaryData);
    }
  PROTOBUF_C_ASSERT_NOT_REACHED ();
  return 0;
}

#include "pbmod_pbuf.c"
#include "pbmod_pres.c"
