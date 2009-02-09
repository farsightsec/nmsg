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

static nmsg_res
pres_to_pbuf(struct nmsg_pbmod *mod, void *cl, const char *pres) {
	ProtobufCMessage *m;
	char *line = NULL, *name = NULL, *saveptr = NULL;
	const char *value = NULL;
	int *qptr;
	nmsg_res res;
	size_t len;
	struct nmsg_pbmod_clos *clos = (struct nmsg_pbmod_clos *) cl;
	struct nmsg_pbmod_field *field;
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
		clos->mode = nmsg_pbmod_clos_m_keyval;
	}

	/* convenience reference */
	m = (ProtobufCMessage *) clos->nmsg_pbuf;

	/* return pbuf ready if the end-of-message marker was seen */
	if (pres[0] == '\n' && clos->mode == nmsg_pbmod_clos_m_keyval) {
		clos->mode = nmsg_pbmod_clos_m_keyval;
		return (nmsg_res_pbuf_ready);
	}

	/* single line data types, and the type tag of a multiline string */
	if (clos->mode == nmsg_pbmod_clos_m_keyval) {
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
		if (field->type != nmsg_pbmod_ft_mlstring)
			value = strtok_r(NULL, " ", &saveptr);
	} else if (clos->mode == nmsg_pbmod_clos_m_multiline) {
		field = clos->field;
		value = pres;
	}

	/* load the value */
	if (PBFIELD_REPEATED(field)) {
		/* XXX */
	} else {
		ptr = PBFIELD(m, field, void);
		qptr = PBFIELD_Q(m, field);

		res = pres_to_pbuf_load(field, clos, value, ptr, qptr);
		if (res != nmsg_res_success)
			return (res);
	}

	return (nmsg_res_success);
}

static nmsg_res
pres_to_pbuf_load(struct nmsg_pbmod_field *field, struct nmsg_pbmod_clos *clos,
		  const char *value, void *ptr, int *qptr)
{
	unsigned i;

	switch (field->type) {
	case nmsg_pbmod_ft_enum: {
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
	case nmsg_pbmod_ft_string: {
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
	case nmsg_pbmod_ft_ip: {
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
			*qptr = 1;

		break;
	}
	case nmsg_pbmod_ft_uint16: {
		char *t;
		long intval;

		intval = strtoul(value, &t, 0);
		if (*t != '\0' || intval > UINT16_MAX)
			return (nmsg_res_parse_error);
		*(uint16_t *) ptr = (uint16_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}
	case nmsg_pbmod_ft_uint32: {
		char *t;
		long intval;

		intval = strtoul(value, &t, 0);
		if (*t != '\0' || intval > UINT32_MAX)
			return (nmsg_res_parse_error);
		*(uint32_t *) ptr = (uint32_t) intval;
		if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL)
			*qptr = 1;
		break;
	}

	case nmsg_pbmod_ft_mlstring:
	/* if we are in keyval mode and the field type is multiline,
	 * there is no value data to read yet */
		if (clos->mode == nmsg_pbmod_clos_m_keyval) {
			clos->field = field;
			clos->mode = nmsg_pbmod_clos_m_multiline;
		} else if (clos->mode == nmsg_pbmod_clos_m_multiline) {
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

				clos->mode = nmsg_pbmod_clos_m_keyval;
			} else {
				nmsg_strbuf_append(sb, "%s", value);
				clos->estsz += len;
			}
		}
		break;
	} /* end switch */

	return (nmsg_res_success);
}

static nmsg_res
pres_to_pbuf_finalize(struct nmsg_pbmod *mod, void *cl, uint8_t **pbuf,
		      size_t *sz)
{
	ProtobufCMessage *m;
	struct nmsg_pbmod_clos *clos = (struct nmsg_pbmod_clos *) cl;
	struct nmsg_pbmod_field *field;
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
		    field->type == nmsg_pbmod_ft_mlstring &&
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
		if (field->descr->type == PROTOBUF_C_TYPE_BYTES &&
		    *PBFIELD_HAS(m, field) == true)
		{
			/* for mlstring's, bdata->data is only a pointer to
			 * the inside of a strbuf */
			if (field->type != nmsg_pbmod_ft_mlstring) {
				ProtobufCBinaryData *bdata;

				bdata = PBFIELD(m, field, ProtobufCBinaryData);
				free(bdata->data);
			} else {
				sb = &clos->strbufs[field->descr->id - 1];
				nmsg_strbuf_reset(sb);
			}
		}
	}

	/* cleanup */
	free(clos->nmsg_pbuf);
	clos->nmsg_pbuf = NULL;
	clos->estsz = 0;

	return (nmsg_res_success);
}
