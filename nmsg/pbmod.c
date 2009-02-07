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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "private.h"
#include "pbmod.h"
#include "res.h"

/* Macros. */

#define NMSG_PBUF_FIELD(type) ((type *) &(clos->nmsg_pbuf)[field->descr->offset])
#define NMSG_PBUF_FIELD_HAS ((protobuf_c_boolean *) &(clos->nmsg_pbuf)[field->descr->quantifier_offset])
#define LINECMP(line, str) (strncmp(line, str, sizeof(str) - 1) == 0)

#define DEFAULT_MULTILINE_SZ	1024

/* Forward. */

static nmsg_res module_init(struct nmsg_pbmod *mod, void **clos);
static nmsg_res module_fini(struct nmsg_pbmod *mod, void **clos);
static nmsg_res module_pres_to_pbuf(struct nmsg_pbmod *mod, void *clos,
				    const char *pres);
static nmsg_res module_pres_to_pbuf_finalize(struct nmsg_pbmod *mod, void *clos,
					     uint8_t **pbuf, size_t *sz);

/* Export. */

nmsg_res
nmsg_pbmod_init(nmsg_pbmod mod, void **clos, int debug) {
	if (mod->init != NULL) {
		return (mod->init(clos, debug));
	} else if (mod->descr != NULL && mod->fields != NULL) {
		return (module_init(mod, clos));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_fini(nmsg_pbmod mod, void **clos) {
	if (mod->fini != NULL) {
		return (mod->fini(clos));
	} else if (mod->descr != NULL && mod->fields != NULL) {
		return (module_fini(mod, clos));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_pbuf2pres(struct nmsg_pbmod *mod, Nmsg__NmsgPayload *np, char **pres,
		     const char *endline)
{
	if (mod->pbuf2pres != NULL) {
		return (mod->pbuf2pres(np, pres, endline));
	} else if (mod->descr != NULL && mod->fields != NULL) {
		return (nmsg_res_notimpl);
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_pres2pbuf(struct nmsg_pbmod *mod, void *clos, const char *pres) {
	if (mod->pres2pbuf != NULL) {
		return (mod->pres2pbuf(clos, pres));
	} else if (mod->descr != NULL && mod->fields != NULL) {
		return (module_pres_to_pbuf(mod, clos, pres));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_pres2pbuf_finalize(struct nmsg_pbmod *mod, void *clos,
			      uint8_t **pbuf, size_t *sz)
{
	if (mod->pres2pbuf_finalize != NULL) {
		return (mod->pres2pbuf_finalize(clos, pbuf, sz));
	} else if (mod->descr != NULL && mod->fields != NULL) {
		return (module_pres_to_pbuf_finalize(mod, clos, pbuf, sz));
	} else {
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_pbmod_field2pbuf(struct nmsg_pbmod *mod, void *clos, const char *field,
		      const uint8_t *val, size_t len, uint8_t **pbuf,
		      size_t *sz)
{
	if (mod->field2pbuf != NULL)
		return (mod->field2pbuf(clos, field, val, len, pbuf, sz));
	else
		return (nmsg_res_notimpl);
}

/* Private. */

static nmsg_res
module_init(struct nmsg_pbmod *mod, void **cl) {
	struct nmsg_pbmod_clos **clos = (struct nmsg_pbmod_clos **) cl;
	struct nmsg_pbmod_field *field;

	/* allocate the closure */
	*clos = calloc(1, sizeof(struct nmsg_pbmod_clos));
	if (*clos == NULL) {
		return (nmsg_res_memfail);
	}

	/* allocate space for pointers to multiline buffers */
	(*clos)->multiline_bufs = calloc(1, (sizeof(struct nmsg_strbuf)) *
					 mod->descr->n_fields);
	if ((*clos)->multiline_bufs == NULL) {
		free(*clos);
		return (nmsg_res_memfail);
	}

	/* allocate multiline buffers */
	for (field = &mod->fields[0]; field->descr != NULL; field++) {
		if (field->type == nmsg_pbmod_ft_multiline_string) {
			struct nmsg_strbuf **sb;

			sb = &(*clos)->multiline_bufs[field->descr->id - 1];
			*sb = calloc(1, sizeof(**sb));
			if (*sb == NULL) {
				free((*clos)->multiline_bufs);
				free(*clos);
				return (nmsg_res_memfail);
			}
			(*sb)->data = (*sb)->pos = calloc(1, DEFAULT_MULTILINE_SZ);
			(*sb)->bufsz = DEFAULT_MULTILINE_SZ;
			if ((*sb)->data == NULL) {
				free(*sb);
				free((*clos)->multiline_bufs);
				free(*clos);
				return (nmsg_res_memfail);
			}
		}
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
	for (field = &mod->fields[0]; field->descr != NULL; field++) {
		if (field->type == nmsg_pbmod_ft_multiline_string) {
			struct nmsg_strbuf **sb;

			sb = &(*clos)->multiline_bufs[field->descr->id - 1];
			free((*sb)->data);
			free(*sb);
		}
	}

	/* deallocate multiline buffer pointers */
	free((*clos)->multiline_bufs);

	/* deallocate closure */
	free(*clos);
	*clos = NULL;

	return (nmsg_res_success);
}

static nmsg_res
module_pres_to_pbuf(struct nmsg_pbmod *mod, void *cl, const char *pres) {
	char *line = NULL, *name = NULL, *value = NULL, *saveptr = NULL;
	struct nmsg_pbmod_field *field;
	struct nmsg_pbmod_clos *clos = (struct nmsg_pbmod_clos *) cl;
	unsigned i;

	/* initialize the in-memory protobuf message if necessary */
	if (clos->nmsg_pbuf == NULL) {
		ProtobufCMessage *base;

		clos->nmsg_pbuf = calloc(1, mod->descr->sizeof_message);
		if (clos->nmsg_pbuf == NULL) {
			return (nmsg_res_memfail);
		}
		base = (ProtobufCMessage *) &(clos->nmsg_pbuf)[0];
		base->descriptor = mod->descr;
		clos->mode = nmsg_pbmod_clos_m_keyval;
	}

	/* return pbuf ready if the end-of-message marker was seen */
	if (pres[0] == '\n' && clos->mode == nmsg_pbmod_clos_m_keyval) {
		clos->mode = nmsg_pbmod_clos_m_keyval;
		return (nmsg_res_pbuf_ready);
	}

	/* find the key and load the value */
	if (clos->mode == nmsg_pbmod_clos_m_keyval) {
		size_t len;

		/* make a copy of the line */
		len = strlen(pres);
		line = alloca(len);
		memcpy(line, pres, len);

		/* trim the newline at the end of the line */
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';

		/* find the key */
		name = strtok_r(line, ":", &saveptr);
		if (name == NULL)
			return (nmsg_res_parse_error);

		/* find the field named by this key */
		for (field = &mod->fields[0]; field->descr != NULL; field++) {
			if (strcmp(name, field->descr->name) == 0)
				break;
		}
		if (field->descr == NULL)
			return (nmsg_res_parse_error);

		/* find the value */
		if (field->type != nmsg_pbmod_ft_multiline_string)
			value = strtok_r(NULL, " ", &saveptr);

		/* load the value */
		switch (field->type) {
		case nmsg_pbmod_ft_enum: {
			bool enum_found;
			ProtobufCEnumDescriptor *enum_descr;

			enum_found = false;
			enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;
			for (i = 0; i < enum_descr->n_values; i++) {
				if (strcmp(enum_descr->values[i].name, value) == 0) {
					enum_found = true;
					*NMSG_PBUF_FIELD(unsigned) =
						enum_descr->values[i].value;
					if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
						*NMSG_PBUF_FIELD_HAS = true;
				}
			}
			if (enum_found == false)
				return (nmsg_res_parse_error);
			*NMSG_PBUF_FIELD(unsigned) = 0;
			clos->estsz += 4;
			break;
		}
		case nmsg_pbmod_ft_string: {
			ProtobufCBinaryData *bdata;

			bdata = NMSG_PBUF_FIELD(ProtobufCBinaryData);
			bdata->data = (uint8_t *) strdup(value);
			if (bdata->data == NULL) {
				return (nmsg_res_memfail);
			}
			bdata->len = strlen(value) + 1; /* \0 terminated */
			clos->estsz += strlen(value);

			if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
				*NMSG_PBUF_FIELD_HAS = true;
			break;
		}
		case nmsg_pbmod_ft_ip: {
			ProtobufCBinaryData *bdata;
			char addr[16];

			bdata = NMSG_PBUF_FIELD(ProtobufCBinaryData);
			if (inet_pton(AF_INET, value, addr) == 1) {
				bdata->data = malloc(4);
				if (bdata->data == NULL) {
					return (nmsg_res_memfail);
				}
				bdata->len = 4;
				memcpy(bdata->data, addr, 4);
				clos->estsz += 4;
			} else if (inet_pton(AF_INET6, value, addr) == 1) {
				bdata->len = 16;
				bdata->data = malloc(16);
				if (bdata->data == NULL) {
					return (nmsg_res_memfail);
				}
				memcpy(bdata->data, addr, 16);
				clos->estsz += 16;
			} else {
				return (nmsg_res_parse_error);
			}

			if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
				*NMSG_PBUF_FIELD_HAS = true;

			break;
		}
		case nmsg_pbmod_ft_uint16: {
			char *t;
			long intval;

			intval = strtoul(value, &t, 0);
			if (*t != '\0' || intval > UINT16_MAX)
				return (nmsg_res_parse_error);
			*NMSG_PBUF_FIELD(uint16_t) = (uint16_t) intval;
			if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
				*NMSG_PBUF_FIELD_HAS = true;
			break;
		}
		case nmsg_pbmod_ft_uint32: {
			char *t;
			long intval;

			intval = strtoul(value, &t, 0);
			if (*t != '\0' || intval > UINT32_MAX)
				return (nmsg_res_parse_error);
			*NMSG_PBUF_FIELD(uint32_t) = (uint32_t) intval;
			if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
				*NMSG_PBUF_FIELD_HAS = true;
			break;
		}

		case nmsg_pbmod_ft_multiline_string:
		/* if we are in keyval mode and the field type is multiline,
		 * there is no value to read yet */
			if (field->type == nmsg_pbmod_ft_multiline_string) {
				clos->field = field;
				clos->mode = nmsg_pbmod_clos_m_multiline;
			}
			break;
		} /* end switch */
	} else if (clos->mode == nmsg_pbmod_clos_m_multiline) {
		struct nmsg_strbuf *sb;
		size_t len = strlen(pres);

		/* load the saved field */
		field = clos->field;

		/* locate our buffer */
		sb = clos->multiline_bufs[field->descr->id - 1];

		/* check if this is the end */
		if (LINECMP(pres, ".\n")) {
			ProtobufCBinaryData *bdata;

			bdata = NMSG_PBUF_FIELD(ProtobufCBinaryData);
			bdata->len = sb->len;
			bdata->data = (uint8_t *) sb->data;
			*NMSG_PBUF_FIELD_HAS = true;

			clos->mode = nmsg_pbmod_clos_m_keyval;
		} else {
			/* increase the size of the buffer if necessary */
			if ((sb->pos + len + 1) > (sb->data + sb->bufsz)) {
				ptrdiff_t cur_offset = sb->pos - sb->data;

				sb->data = realloc(sb->data, sb->bufsz * 2);
				if (sb->data == NULL) {
					sb->pos = NULL;
					return (nmsg_res_memfail);
				}
				sb->bufsz *= 2;
				sb->pos = sb->data + cur_offset;
			}

			strncpy(sb->pos, pres, len);
			sb->pos[len] = '\0';
			sb->pos += len;
			sb->len += len;
			clos->estsz += len;
		}
	}

	return (nmsg_res_success);
}

static nmsg_res
module_pres_to_pbuf_finalize(struct nmsg_pbmod *mod, void *cl,
			     uint8_t **pbuf, size_t *sz)
{
	struct nmsg_pbmod_clos *clos = (struct nmsg_pbmod_clos *) cl;
	struct nmsg_pbmod_field *field;
	struct nmsg_strbuf *sb;

	if (clos->estsz < 64)
		clos->estsz = 64;

	/* allocate a buffer for the serialized message */
	*pbuf = malloc(2 * clos->estsz);
	if (*pbuf == NULL) {
		free(clos->nmsg_pbuf);
		return (nmsg_res_memfail);
	}

	/* null terminate multiline strings */
	for (field = &mod->fields[0]; field->descr != NULL; field++) {
		if (field->descr->type == PROTOBUF_C_TYPE_BYTES &&
		    field->type == nmsg_pbmod_ft_multiline_string &&
		    *NMSG_PBUF_FIELD_HAS == true)
		{
			ProtobufCBinaryData *bdata;

			bdata = NMSG_PBUF_FIELD(ProtobufCBinaryData);
			bdata->len += 1;
		}
	}

	/* serialize the message */
	*sz = protobuf_c_message_pack((const ProtobufCMessage *) clos->nmsg_pbuf,
				      *pbuf);

	/* deallocate any byte arrays field members */
	for (field = &mod->fields[0]; field->descr != NULL; field++) {
		if (field->descr->type == PROTOBUF_C_TYPE_BYTES &&
		    *NMSG_PBUF_FIELD_HAS == true)
		{
			if (field->type != nmsg_pbmod_ft_multiline_string) {
				ProtobufCBinaryData *bdata;

				bdata = NMSG_PBUF_FIELD(ProtobufCBinaryData);
				free(bdata->data);
			} else {
				sb = clos->multiline_bufs[field->descr->id - 1];
				if (sb->bufsz > DEFAULT_MULTILINE_SZ)
					sb->data = realloc(sb->data, DEFAULT_MULTILINE_SZ);
				sb->pos = sb->data;
				sb->len = 0;
			}
		}
	}

	/* cleanup */
	free(clos->nmsg_pbuf);
	clos->nmsg_pbuf = NULL;
	clos->estsz = 0;
	return (nmsg_res_success);
}
