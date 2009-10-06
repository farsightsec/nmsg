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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nmsg.h"
#include "private.h"

#include "transparent.h"

nmsg_res
_nmsg_msgmod_module_init(struct nmsg_msgmod *mod, void **cl) {
	struct nmsg_msgmod_clos **clos = (struct nmsg_msgmod_clos **) cl;
	struct nmsg_msgmod_field *field;
	unsigned max_fieldid = 0;

	/* allocate the closure */
	*clos = calloc(1, sizeof(struct nmsg_msgmod_clos));
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

nmsg_res
_nmsg_msgmod_module_fini(struct nmsg_msgmod *mod, void **cl) {
	struct nmsg_msgmod_clos **clos = (struct nmsg_msgmod_clos **) cl;
	struct nmsg_msgmod_field *field;

	/* deallocate serialized message buffer */
	free((*clos)->nmsg_pbuf);

	/* deallocate multiline buffers */
	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->type == nmsg_msgmod_ft_mlstring) {
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

nmsg_res
_nmsg_msgmod_payload_to_pres(struct nmsg_msgmod *mod, Nmsg__NmsgPayload *np,
			     char **pres, const char *endline)
{
	ProtobufCMessage *m;
	nmsg_res res;
	struct nmsg_msgmod_field *field;
	struct nmsg_strbuf *sb;

	/* unpack message */
	if (np->has_payload == 0)
		return (nmsg_res_failure);
	m = protobuf_c_message_unpack(mod->pbdescr, NULL, np->payload.len,
				      np->payload.data);

	/* allocate pres str buffer */
	sb = nmsg_strbuf_init();
	if (sb == NULL)
		return (nmsg_res_memfail);

	/* convert each message field to presentation format */
	for (field = mod->fields; field->descr != NULL; field++) {
		void *ptr;

		if (PBFIELD_ONE_PRESENT(m, field)) {
			ptr = PBFIELD(m, field, void);

			res = _nmsg_msgmod_payload_to_pres_load(field, ptr, sb, endline);
			if (res != nmsg_res_success) {
				nmsg_strbuf_destroy(&sb);
				return (res);
			}
		} else if (PBFIELD_REPEATED(field)) {
			size_t n, n_entries;

			n_entries = *PBFIELD_Q(m, field);
			for (n = 0; n < n_entries; n++) {
				ptr = PBFIELD(m, field, void);
				char *array = *(char **) ptr;
				size_t siz = sizeof_elt_in_repeated_array(field->descr->type);

				res = _nmsg_msgmod_payload_to_pres_load(field, &array[n * siz], sb, endline);
				if (res != nmsg_res_success) {
					nmsg_strbuf_destroy(&sb);
					return (res);
				}
			}
		}
	}

	/* cleanup */
	*pres = sb->data;
	free(sb);
	protobuf_c_message_free_unpacked(m, NULL);

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_payload_to_pres_load(struct nmsg_msgmod_field *field, void *ptr,
				  struct nmsg_strbuf *sb, const char *endline)
{
	ProtobufCBinaryData *bdata;
	unsigned i;

	switch (field->type) {
	case nmsg_msgmod_ft_string:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s: %s%s",
				   field->descr->name,
				   bdata->data,
				   endline);
		break;
	case nmsg_msgmod_ft_mlstring:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s:%s%s.%s",
				   field->descr->name,
				   endline,
				   bdata->data,
				   endline);
		break;
	case nmsg_msgmod_ft_enum: {
		ProtobufCEnumDescriptor *enum_descr;
		bool enum_found;
		unsigned enum_value;

		enum_found = false;
		enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;

		enum_value = *((unsigned *) ptr);
		for (i = 0; i < enum_descr->n_values; i++) {
			if ((unsigned) enum_descr->values[i].value == enum_value) {
				nmsg_strbuf_append(sb, "%s: %s%s",
						   field->descr->name,
						   enum_descr->values[i].name,
						   endline);
				enum_found = true;
			}
		}
		if (enum_found == false) {
			nmsg_strbuf_append(sb, "%s: <UNKNOWN ENUM>%s",
					   field->descr->name,
					   endline);
		}
		break;
	}
	case nmsg_msgmod_ft_ip: {
		char sip[INET6_ADDRSTRLEN];

		bdata = (ProtobufCBinaryData *) ptr;
		if (bdata->len == 4) {
			if (inet_ntop(AF_INET, bdata->data, sip, sizeof(sip))) {
				nmsg_strbuf_append(sb, "%s: %s%s",
						   field->descr->name,
						   sip, endline);
			}
		} else if (bdata->len == 16) {
			if (inet_ntop(AF_INET6, bdata->data, sip, sizeof(sip))) {
				nmsg_strbuf_append(sb, "%s: %s%s",
						   field->descr->name,
						   sip, endline);
			}
		} else {
			nmsg_strbuf_append(sb, "%s: <INVALID IP len=%zd>%s",
					   field->descr->name, bdata->len,
					   endline);
		}
		break;
	}
	case nmsg_msgmod_ft_uint16:
		nmsg_strbuf_append(sb, "%s: %hu%s",
				   field->descr->name,
				   *((uint16_t *) ptr), endline);
		break;
	case nmsg_msgmod_ft_uint32:
		nmsg_strbuf_append(sb, "%s: %u%s",
				   field->descr->name,
				   *((uint32_t *) ptr), endline);
		break;
	case nmsg_msgmod_ft_uint64:
		nmsg_strbuf_append(sb, "%s: %" PRIu64 "%s",
				   field->descr->name,
				   *((uint64_t *) ptr), endline);
		break;
	case nmsg_msgmod_ft_int16:
		nmsg_strbuf_append(sb, "%s: %hd%s",
				   field->descr->name,
				   *((int16_t *) ptr), endline);
		break;
	case nmsg_msgmod_ft_int32:
		nmsg_strbuf_append(sb, "%s: %d%s",
				   field->descr->name,
				   *((int32_t *) ptr), endline);
		break;
	case nmsg_msgmod_ft_int64:
		nmsg_strbuf_append(sb, "%s: %" PRIi64 "%s",
				   field->descr->name,
				   *((int64_t *) ptr), endline);
		break;
	} /* end switch */

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_pres_to_payload(struct nmsg_msgmod *mod, void *cl, const char *pres) {
	ProtobufCMessage *m;
	char *line = NULL, *name = NULL, *saveptr = NULL;
	const char *value = NULL;
	int *qptr;
	nmsg_res res;
	size_t len;
	struct nmsg_msgmod_clos *clos = (struct nmsg_msgmod_clos *) cl;
	struct nmsg_msgmod_field *field = NULL;
	void *ptr;

	/* initialize the in-memory protobuf message if necessary */
	if (clos->nmsg_pbuf == NULL) {
		ProtobufCMessage *base;

		clos->nmsg_pbuf = calloc(1, mod->pbdescr->sizeof_message);
		if (clos->nmsg_pbuf == NULL) {
			return (nmsg_res_memfail);
		}
		base = (ProtobufCMessage *) &(clos->nmsg_pbuf)[0];
		base->descriptor = mod->pbdescr;
		clos->mode = nmsg_msgmod_clos_m_keyval;
	}

	/* convenience reference */
	m = (ProtobufCMessage *) clos->nmsg_pbuf;

	/* return pbuf ready if the end-of-message marker was seen */
	if (pres[0] == '\n' && clos->mode == nmsg_msgmod_clos_m_keyval) {
		clos->mode = nmsg_msgmod_clos_m_keyval;
		return (nmsg_res_pbuf_ready);
	}

	/* single line data types, and the type tag of a multiline string */
	if (clos->mode == nmsg_msgmod_clos_m_keyval) {
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
		for (field = mod->fields; field->descr != NULL; field++) {
			if (strcmp(name, field->descr->name) == 0)
				break;
		}

		if (field->descr == NULL)
			return (nmsg_res_parse_error);

		/* find the value */
		if (field->type != nmsg_msgmod_ft_mlstring)
			value = strtok_r(NULL, " ", &saveptr);

		/* reject truncated values */
		if (value == NULL)
			return (nmsg_res_parse_error);
	} else if (clos->mode == nmsg_msgmod_clos_m_multiline) {
		field = clos->field;
		value = pres;
	}

	/* load the value */
	if (PBFIELD_REPEATED(field)) {
		char **parray;
		int n;
		size_t bytes_needed, siz;

		parray = (char **) PBFIELD(m, field, void);
		qptr = PBFIELD_Q(m, field);
		siz = sizeof_elt_in_repeated_array(field->descr->type);
		bytes_needed = (*qptr + 1) * siz;

		n = *qptr;
		*qptr += 1;

		ptr = realloc(*parray, bytes_needed);
		if (ptr == NULL) {
			free(*parray);
			return (nmsg_res_memfail);
		}
		*parray = ptr;

		ptr = &((*parray)[n * siz]);
		memset(ptr, 0, siz);

		res = _nmsg_msgmod_pres_to_payload_load(field, clos, value, ptr, qptr);
		if (res != nmsg_res_success)
			return (res);
	} else {
		ptr = PBFIELD(m, field, void);
		qptr = PBFIELD_Q(m, field);

		res = _nmsg_msgmod_pres_to_payload_load(field, clos, value, ptr, qptr);
		if (res != nmsg_res_success)
			return (res);
	}

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_pres_to_payload_load(struct nmsg_msgmod_field *field,
				  struct nmsg_msgmod_clos *clos,
				  const char *value, void *ptr, int *qptr)
{
	unsigned i;

	switch (field->type) {
	case nmsg_msgmod_ft_enum: {
		bool enum_found;
		ProtobufCEnumDescriptor *enum_descr;

		enum_found = false;
		enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;
		for (i = 0; i < enum_descr->n_values; i++) {
			if (strcmp(enum_descr->values[i].name, value) == 0) {
				enum_found = true;
				*(unsigned *) ptr = enum_descr->values[i].value;

				if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
					*qptr = 1;
				clos->estsz += 4;
				break;
			}
		}
		if (enum_found == false)
			return (nmsg_res_parse_error);
		break;
	}
	case nmsg_msgmod_ft_string: {
		ProtobufCBinaryData *bdata;

		bdata = ptr;
		bdata->data = (uint8_t *) strdup(value);
		if (bdata->data == NULL) {
			return (nmsg_res_memfail);
		}
		bdata->len = strlen(value) + 1; /* \0 terminated */
		clos->estsz += strlen(value);

		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}
	case nmsg_msgmod_ft_ip: {
		ProtobufCBinaryData *bdata;
		char addr[16];

		bdata = ptr;
		if (inet_pton(AF_INET, value, addr) == 1) {
			bdata->data = malloc(4);
			if (bdata->data == NULL) {
				return (nmsg_res_memfail);
			}
			bdata->len = 4;
			memcpy(bdata->data, addr, 4);
			clos->estsz += 4;
		} else if (inet_pton(AF_INET6, value, addr) == 1) {
			bdata->data = malloc(16);
			if (bdata->data == NULL) {
				return (nmsg_res_memfail);
			}
			bdata->len = 16;
			memcpy(bdata->data, addr, 16);
			clos->estsz += 16;
		} else {
			return (nmsg_res_parse_error);
		}

		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;

		break;
	}
	case nmsg_msgmod_ft_uint16: {
		char *t;
		unsigned long intval;

		intval = strtoul(value, &t, 0);
		if (*t != '\0' || intval > UINT16_MAX)
			return (nmsg_res_parse_error);
		*(uint16_t *) ptr = (uint16_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		char *t;
		long intval;

		intval = strtoul(value, &t, 0);
		if (*t != '\0')
			return (nmsg_res_parse_error);
		*(uint32_t *) ptr = (uint32_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		char *t;
		unsigned long long intval;

		intval = strtoull(value, &t, 0);
		if (*t != '\0')
			return (nmsg_res_parse_error);
		*(uint64_t *) ptr = (uint64_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}
	case nmsg_msgmod_ft_int16: {
		char *t;
		long intval;

		intval = strtol(value, &t, 0);
		if (*t != '\0' || intval > INT16_MAX)
			return (nmsg_res_parse_error);
		*(int16_t *) ptr = (int16_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}
	case nmsg_msgmod_ft_int32: {
		char *t;
		long intval;

		intval = strtol(value, &t, 0);
		if (*t != '\0')
			return (nmsg_res_parse_error);
		*(int32_t *) ptr = (int32_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}
	case nmsg_msgmod_ft_int64: {
		char *t;
		long long intval;

		intval = strtoll(value, &t, 0);
		if (*t != '\0')
			return (nmsg_res_parse_error);
		*(int64_t *) ptr = (int64_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}

	case nmsg_msgmod_ft_mlstring:
	/* if we are in keyval mode and the field type is multiline,
	 * there is no value data to read yet */
		if (clos->mode == nmsg_msgmod_clos_m_keyval) {
			clos->field = field;
			clos->mode = nmsg_msgmod_clos_m_multiline;
		} else if (clos->mode == nmsg_msgmod_clos_m_multiline) {
			struct nmsg_strbuf *sb;
			size_t len = strlen(value);

			/* load the saved field */
			field = clos->field;

			/* locate our buffer */
			sb = &clos->strbufs[field->descr->id - 1];

			/* check if this is the end */
			if (LINECMP(value, ".\n")) {
				ProtobufCBinaryData *bdata;

				bdata = ptr;
				bdata->len = nmsg_strbuf_len(sb);
				bdata->data = (uint8_t *) sb->data;
				if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
					*qptr = 1;

				clos->mode = nmsg_msgmod_clos_m_keyval;
			} else {
				nmsg_strbuf_append(sb, "%s", value);
				clos->estsz += len;
			}
		}
		break;
	} /* end switch */

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_pres_to_payload_finalize(struct nmsg_msgmod *mod, void *cl,
				      uint8_t **pbuf, size_t *sz)
{
	ProtobufCMessage *m;
	struct nmsg_msgmod_clos *clos = (struct nmsg_msgmod_clos *) cl;
	struct nmsg_msgmod_field *field;
	struct nmsg_strbuf *sb;

	/* guarantee a minimum allocation */
	if (clos->estsz < 64)
		clos->estsz = 64;

	/* convenience reference */
	m = (ProtobufCMessage *) clos->nmsg_pbuf;

	/* allocate a buffer for the serialized message */
	*pbuf = malloc(2 * clos->estsz);
	if (*pbuf == NULL) {
		free(clos->nmsg_pbuf);
		return (nmsg_res_memfail);
	}

	/* null terminate multiline strings */
	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->descr->type == PROTOBUF_C_TYPE_BYTES &&
		    field->type == nmsg_msgmod_ft_mlstring &&
		    PBFIELD_ONE_PRESENT(m, field))
		{
			ProtobufCBinaryData *bdata;

			bdata = PBFIELD(m, field, ProtobufCBinaryData);
			bdata->len += 1;
		}
	}

	/* serialize the message */
	*sz = protobuf_c_message_pack(m, *pbuf);

	/* deallocate any byte arrays field members */
	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->descr->type != PROTOBUF_C_TYPE_BYTES)
			continue;

		if (field->descr->label == PROTOBUF_C_LABEL_REQUIRED ||
		    (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL &&
		     *PBFIELD_Q(m, field) == 1))
		{
			/* for mlstring's, bdata->data is only a pointer to
			 * the inside of a strbuf */
			if (field->type == nmsg_msgmod_ft_mlstring) {
				sb = &clos->strbufs[field->descr->id - 1];
				nmsg_strbuf_reset(sb);
			} else {
				ProtobufCBinaryData *bdata;

				bdata = PBFIELD(m, field, ProtobufCBinaryData);
				if (bdata && bdata->data)
					free(bdata->data);
			}
		}
		else if (field->descr->label == PROTOBUF_C_LABEL_REPEATED &&
			 *PBFIELD_Q(m, field) >= 1)
		{
			/* XXX we can't have repeated mlstring's */
			assert(field->type != nmsg_msgmod_ft_mlstring);

			char **parray;
			int n, *qptr;
			size_t siz;

			parray = (char **) PBFIELD(m, field, void);
			qptr = PBFIELD_Q(m, field);
			siz = sizeof_elt_in_repeated_array(field->descr->type);

			for (n = 0; n < *qptr; n++) {
				ProtobufCBinaryData *bdata;

				bdata = (ProtobufCBinaryData *) &((*parray)[n * siz]);
				free(bdata->data);
			}
			free(*parray);
		}
	}

	/* cleanup */
	free(clos->nmsg_pbuf);
	clos->nmsg_pbuf = NULL;
	clos->estsz = 0;

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_load_field_descriptors(struct nmsg_msgmod *mod) {
	const ProtobufCFieldDescriptor *pbfield;
	struct nmsg_msgmod_field *field;
	unsigned i;

	/* lookup the field descriptors by name */
	for (field = mod->fields; field->name != NULL; field++) {
		bool descr_found = false;

		for (i = 0; i < mod->pbdescr->n_fields; i++) {
			pbfield = &mod->pbdescr->fields[i];
			if (strcmp(pbfield->name, field->name) == 0) {
				descr_found = true;
				field->descr = pbfield;
				break;
			}
		}
		if (descr_found == false)
			return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

nmsg_res
_nmsg_msgmod_message_reset(struct nmsg_msgmod *mod, void *m) {
	ProtobufCBinaryData *bdata;
	struct nmsg_msgmod_field *field;

	for (field = mod->fields; field->descr != NULL; field++) {
		if (field->type == nmsg_msgmod_ft_ip ||
		    field->type == nmsg_msgmod_ft_string ||
		    field->type == nmsg_msgmod_ft_mlstring)
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
