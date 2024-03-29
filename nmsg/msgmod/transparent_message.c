/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2009-2012, 2015-2016, 2019 by Farsight Security, Inc.
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

/* Import. */

#include "private.h"

#include "transparent.h"

/* Macros. */

#define CHECK_TRANSPARENT() do { \
	if (msg->mod == NULL || msg->mod->plugin == NULL || \
	    msg->mod->plugin->type != nmsg_msgmod_type_transparent || \
	    msg->mod->plugin->pbdescr == NULL) \
		return (nmsg_res_failure); \
} while(0);

#define DESERIALIZE() do { \
	nmsg_res c_t_res; \
	c_t_res = _nmsg_message_deserialize(msg); \
	if (c_t_res != nmsg_res_success) \
		return (c_t_res); \
} while(0);

#define GET_FIELD(idx) do { \
	if (field_idx > msg->mod->n_fields - 1) \
		return (nmsg_res_failure); \
	field = &msg->mod->fields[field_idx]; \
} while(0);

/* Export: getters. */

nmsg_res
nmsg_message_get_num_fields(struct nmsg_message *msg, size_t *n_fields) {
	CHECK_TRANSPARENT();
	*n_fields = msg->mod->n_fields;
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field_name(struct nmsg_message *msg, unsigned field_idx,
			    const char **field_name)
{
	struct nmsg_msgmod_field *field;
	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);
	*field_name = field->name;
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field_idx(struct nmsg_message *msg, const char *field_name,
			   unsigned *idx)
{
	struct nmsg_msgmod_field *field;
	CHECK_TRANSPARENT();

	field = _nmsg_msgmod_lookup_field(msg->mod, field_name);
	if (field == NULL)
		return (nmsg_res_failure);

	*idx = field - &msg->mod->fields[0];
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_num_field_values_by_idx(struct nmsg_message *msg,
					 unsigned field_idx,
					 size_t *n_field_values)
{
	struct nmsg_msgmod_field *field;

	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);
	DESERIALIZE();

	if (field->descr == NULL) {
		if (field->get == NULL) {
			return (nmsg_res_failure);
		}
		*n_field_values = 0;
		nmsg_res res = nmsg_res_success;
		for (unsigned val_idx = 0; res == nmsg_res_success; val_idx++) {
			void *data = NULL;
			size_t len = 0;

			res = field->get(msg, field, val_idx, &data, &len, msg->msg_clos);
			if (res == nmsg_res_success) {
				*n_field_values += 1;
			}
		}
		return (nmsg_res_success);
	}

	if (field->descr->label == PROTOBUF_C_LABEL_REQUIRED) {
		*n_field_values = 1;
		return (nmsg_res_success);
	} else if (field->descr->label == PROTOBUF_C_LABEL_OPTIONAL ||
		   field->descr->label == PROTOBUF_C_LABEL_REPEATED)
	{
		*n_field_values = *PBFIELD_Q(msg->message, field);
		return (nmsg_res_success);
	}

	return (nmsg_res_failure);
}

nmsg_res
nmsg_message_get_num_field_values(struct nmsg_message *msg,
				  const char *field_name,
				  size_t *n_field_values)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_get_num_field_values_by_idx(msg, field_idx, n_field_values));
	else
		return (nmsg_res_failure);
}

nmsg_res
nmsg_message_get_field_flags_by_idx(struct nmsg_message *msg,
				    unsigned field_idx,
				    unsigned *flags)
{
	struct nmsg_msgmod_field *field;
	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);
	*flags = field->flags;
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field_flags(struct nmsg_message *msg,
			     const char *field_name,
			     unsigned *flags)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_get_field_flags_by_idx(msg, field_idx, flags));
	else
		return (nmsg_res_failure);
}

nmsg_res
nmsg_message_get_field_type_by_idx(struct nmsg_message *msg,
				   unsigned field_idx,
				   nmsg_msgmod_field_type *type)
{
	struct nmsg_msgmod_field *field;
	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);
	*type = field->type;
	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field_type(struct nmsg_message *msg,
			    const char *field_name,
			    nmsg_msgmod_field_type *type)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_get_field_type_by_idx(msg, field_idx, type));
	else
		return (nmsg_res_failure);
}

nmsg_res
nmsg_message_get_field_by_idx(nmsg_message_t msg, unsigned field_idx,
			      unsigned val_idx,
			      void **data, size_t *len)
{
	ProtobufCBinaryData *bdata;
	char **parray;
	int *qptr;
	size_t sz;
	struct nmsg_msgmod_field *field;
	void *ptr = NULL;

	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);

	if (field->flags & NMSG_MSGMOD_FIELD_HIDDEN)
		return (nmsg_res_failure);

	DESERIALIZE();

	if (field->get != NULL)
		return (field->get(msg, field, val_idx, data, len, msg->msg_clos));

	qptr = PBFIELD_Q(msg->message, field);

	switch (field->descr->label) {
	case PROTOBUF_C_LABEL_REPEATED:
		sz = sizeof_elt_in_repeated_array(field->descr->type);

		if (val_idx >= (unsigned) *qptr) {
			return (nmsg_res_failure);
		}
		parray = (char **) PBFIELD(msg->message, field, void);
		ptr = *parray + (sz * val_idx);
		break;
#if PROTOBUF_C_VERSION_NUMBER >= 1003000
	case PROTOBUF_C_LABEL_NONE:
		/* FALLTHROUGH */
#endif
	case PROTOBUF_C_LABEL_OPTIONAL:
		if (val_idx >= (unsigned) *qptr)
			return (nmsg_res_failure);
		/* FALLTHROUGH */
	case PROTOBUF_C_LABEL_REQUIRED:
		if (val_idx > 0)
			return (nmsg_res_failure);
		ptr = PBFIELD(msg->message, field, void);
		break;
	}

	assert(ptr != NULL);

	switch (field->type) {
	case nmsg_msgmod_ft_ip:
		/* if the encoded protobuf byte field is not precisely 4 or 16
		 * bytes long, then there is a bug in the encoder. */
		bdata = ptr;
		if (bdata->len != 4 && bdata->len != 16)
			return (nmsg_res_failure);
		/* FALLTHROUGH */
	case nmsg_msgmod_ft_bytes:
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		bdata = ptr;
		if (len)
			*len = bdata->len;
		*data = bdata->data;
		break;
	}

	case nmsg_msgmod_ft_bool:
	case nmsg_msgmod_ft_enum:
		if (len)
			*len = sizeof(unsigned);
		*data = ptr;
		break;

	case nmsg_msgmod_ft_int16:
	case nmsg_msgmod_ft_uint16:
		/* FALLTHROUGH */
	case nmsg_msgmod_ft_int32:
	case nmsg_msgmod_ft_uint32:
		if (len)
			*len = sizeof(int32_t);
		*data = ptr;
		break;

	case nmsg_msgmod_ft_int64:
	case nmsg_msgmod_ft_uint64:
		if (len)
			*len = sizeof(int64_t);
		*data = ptr;
		break;
	
	case nmsg_msgmod_ft_double:
		if (len)
			*len = sizeof(double);
		*data = ptr;
		break;

	default:
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

nmsg_res
nmsg_message_get_field(nmsg_message_t msg, const char *field_name,
		       unsigned val_idx,
		       void **data, size_t *len)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_get_field_by_idx(msg, field_idx, val_idx, data, len));
	else
		return (nmsg_res_failure);
}

/* Export: setters. */

nmsg_res
nmsg_message_set_field_by_idx(struct nmsg_message *msg, unsigned field_idx,
			      unsigned val_idx,
			      const uint8_t *data, size_t len)
{
	char **parray;
	int *qptr;
	size_t sz;
	struct nmsg_msgmod_field *field;
	void *ptr = NULL;

	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);

	if (field->descr == NULL)
		return (nmsg_res_failure);

	DESERIALIZE();

	msg->updated = true;

	qptr = PBFIELD_Q(msg->message, field);

	switch (field->descr->label) {
	case PROTOBUF_C_LABEL_REPEATED:
		sz = sizeof_elt_in_repeated_array(field->descr->type);

		if (val_idx <= (unsigned) *qptr) {
			size_t bytes_needed, bytes_used;

			bytes_used = (*qptr) * sz;
			if (val_idx == (unsigned) *qptr)
				*qptr += 1;
			bytes_needed = (*qptr) * sz;

			assert(bytes_used <= bytes_needed);

			parray = (char **) PBFIELD(msg->message, field, void);

			if (bytes_used < bytes_needed) {
				ptr = realloc(*parray, bytes_needed);
				if (ptr == NULL) {
					free(*parray);
					*qptr = 0;
					*parray = NULL;
					return (nmsg_res_memfail);
				}
				*parray = ptr;

				/* scrub the uninitialized part of the allocation */
				memset(((char *) ptr) + bytes_used, 0, bytes_needed - bytes_used);
			}
		} else {
			return (nmsg_res_failure);
		}
		parray = (char **) PBFIELD(msg->message, field, void);
		ptr = *parray + (sz * val_idx);
		break;
#if PROTOBUF_C_VERSION_NUMBER >= 1003000
	case PROTOBUF_C_LABEL_NONE:
		/* FALLTHROUGH */
#endif
	case PROTOBUF_C_LABEL_OPTIONAL:
		if (val_idx == 0)
			*qptr = 1;
		/* FALLTHROUGH */
	case PROTOBUF_C_LABEL_REQUIRED:
		if (val_idx > 0)
			return (nmsg_res_failure);
		ptr = PBFIELD(msg->message, field, void);
		break;
	}

	assert(ptr != NULL);

	switch (field->type) {
	case nmsg_msgmod_ft_ip:
		/*
		* the user can only supply a byte array of precisely
		* 0, 4 or 16 bytes for this field type
		*/
		if (len != 0 && len != 4 && len != 16)
			return (nmsg_res_failure);
		/* FALLTHROUGH */
	case nmsg_msgmod_ft_bytes:
	case nmsg_msgmod_ft_string:
	case nmsg_msgmod_ft_mlstring: {
		ProtobufCBinaryData *bdata;
		bdata = ptr;
		if (bdata->data != NULL)
			free(bdata->data);
		bdata->len = len;
		if (len > 0) {
			bdata->data = malloc(len);
			if (bdata->data == NULL)
				return (nmsg_res_memfail);
			memcpy(bdata->data, data, len);
		} else {
			bdata->data = NULL;
		}
		break;
	}
	case nmsg_msgmod_ft_bool: {
		bool val, *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_enum: {
		unsigned val, *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_int16: {
		int16_t val;
		int32_t *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_uint16: {
		uint16_t val;
		uint32_t *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_int32: {
		int32_t val, *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_uint32: {
		uint32_t val, *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_int64: {
		int64_t val, *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_uint64: {
		uint64_t val, *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	case nmsg_msgmod_ft_double: {
		double val, *pval;
		pval = ptr;
		memcpy(&val, data, sizeof(val));
		*pval = val;
		break;
	}
	default:
		return (nmsg_res_failure);
	}

	return (nmsg_res_success);
}

nmsg_res
nmsg_message_set_field(nmsg_message_t msg, const char *field_name,
		       unsigned val_idx,
		       const uint8_t *data, size_t len)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_set_field_by_idx(msg, field_idx, val_idx, data, len));
	else
		return (nmsg_res_failure);
}

/* Export: utility functions. */

nmsg_res
nmsg_message_enum_name_to_value(struct nmsg_message *msg, const char *field_name,
				const char *name, unsigned *value)
{
	nmsg_res res;
	unsigned field_idx;

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_enum_name_to_value_by_idx(msg, field_idx, name, value));
	else
		return (nmsg_res_failure);
}

nmsg_res
nmsg_message_enum_name_to_value_by_idx(nmsg_message_t msg, unsigned field_idx,
				       const char *name, unsigned *value)
{
	ProtobufCEnumDescriptor *enum_descr;
	const ProtobufCEnumValue *enum_value;
	struct nmsg_msgmod_field *field;

	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);

	if (field->descr->type != PROTOBUF_C_TYPE_ENUM)
		return (nmsg_res_failure);
	enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;
	if (enum_descr == NULL)
		return (nmsg_res_failure);

	enum_value = protobuf_c_enum_descriptor_get_value_by_name(enum_descr, name);
	if (enum_value == NULL)
		return (nmsg_res_failure);
	*value = (unsigned) enum_value->value;

	return (nmsg_res_success);
}

nmsg_res
nmsg_message_enum_value_to_name(struct nmsg_message *msg, const char *field_name,
				unsigned value, const char **name)
{
	nmsg_res res;
	unsigned field_idx;

	CHECK_TRANSPARENT();

	res = nmsg_message_get_field_idx(msg, field_name, &field_idx);
	if (res == nmsg_res_success)
		return (nmsg_message_enum_value_to_name_by_idx(msg, field_idx, value, name));
	else
		return (res);
}

nmsg_res
nmsg_message_enum_value_to_name_by_idx(struct nmsg_message *msg, unsigned field_idx,
				       unsigned value, const char **name)
{
	ProtobufCEnumDescriptor *enum_descr;
	const ProtobufCEnumValue *enum_value;
	struct nmsg_msgmod_field *field;

	CHECK_TRANSPARENT();
	GET_FIELD(field_idx);

	if (field->descr->type != PROTOBUF_C_TYPE_ENUM)
		return (nmsg_res_failure);
	enum_descr = (ProtobufCEnumDescriptor *) field->descr->descriptor;
	if (enum_descr == NULL)
		return (nmsg_res_failure);

	enum_value = protobuf_c_enum_descriptor_get_value(enum_descr, value);
	if (enum_value == NULL)
		return (nmsg_res_failure);
	*name = enum_value->name;

	return (nmsg_res_success);
}
