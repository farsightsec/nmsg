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
pbuf_to_pres(struct nmsg_pbmod *mod, Nmsg__NmsgPayload *np, char **pres,
	     const char *endline)
{
	ProtobufCMessage *m;
	nmsg_res res;
	struct nmsg_pbmod_field *field;
	struct nmsg_strbuf *sb;

	/* unpack message */
	if (np->has_payload == 0)
		return (nmsg_res_failure);
	m = protobuf_c_message_unpack(mod->pbdescr, NULL, np->payload.len,
				      np->payload.data);

	/* allocate pres str buffer */
	sb = calloc(1, sizeof(*sb));
	if (sb == NULL)
		return (nmsg_res_memfail);

	/* convert each message field to presentation format */
	for (field = mod->fields; field->descr != NULL; field++) {
		void *ptr;

		if (PBFIELD_ONE_PRESENT(m, field)) {
			ptr = PBFIELD(m, field, void);

			res = pbuf_to_pres_load(field, ptr, sb, endline);
			if (res != nmsg_res_success) {
				nmsg_strbuf_free(&sb);
				return (res);
			}
		} else if (PBFIELD_REPEATED(field)) {
			size_t n, n_entries;

			n_entries = *PBFIELD_Q(m, field);
			for (n = 0; n < n_entries; n++) {
				ptr = PBFIELD(m, field, void);
				char *array = *(char **) ptr;
				size_t siz = sizeof_elt_in_repeated_array(field->descr->type);

				res = pbuf_to_pres_load(field, &array[n * siz], sb, endline);
				if (res != nmsg_res_success) {
					nmsg_strbuf_free(&sb);
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

static nmsg_res
pbuf_to_pres_load(struct nmsg_pbmod_field *field, void *ptr,
		  struct nmsg_strbuf *sb, const char *endline)
{
	ProtobufCBinaryData *bdata;
	unsigned i;

	switch (field->type) {
	case nmsg_pbmod_ft_string:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s: %s%s",
				   field->descr->name,
				   bdata->data,
				   endline);
		break;
	case nmsg_pbmod_ft_mlstring:
		bdata = (ProtobufCBinaryData *) ptr;
		nmsg_strbuf_append(sb, "%s:%s%s.%s",
				   field->descr->name,
				   endline,
				   bdata->data,
				   endline);
		break;
	case nmsg_pbmod_ft_enum: {
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
	case nmsg_pbmod_ft_ip: {
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
	case nmsg_pbmod_ft_uint16:
		nmsg_strbuf_append(sb, "%s: %hu%s",
				   field->descr->name,
				   *((uint16_t *) ptr), endline);
		break;
	case nmsg_pbmod_ft_uint32:
		nmsg_strbuf_append(sb, "%s: %u%s",
				   field->descr->name,
				   *((uint32_t *) ptr), endline);
		break;
	} /* end switch */

	return (nmsg_res_success);
}
