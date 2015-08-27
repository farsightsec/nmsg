/*
 * Copyright (c) 2009 by Farsight Security, Inc.
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

#ifndef NMSG_MSGMOD_TRANSPARENT_H
#define NMSG_MSGMOD_TRANSPARENT_H

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

/* Prototypes. */

nmsg_res
_nmsg_msgmod_module_init(struct nmsg_msgmod *mod, void **cl);

nmsg_res
_nmsg_msgmod_module_fini(struct nmsg_msgmod *mod, void **cl);

nmsg_res
_nmsg_message_payload_to_pres(struct nmsg_message *msg, char **pres, const char *endline);

nmsg_res
_nmsg_message_payload_to_pres_load(struct nmsg_message *msg,
				   struct nmsg_msgmod_field *field, void *ptr,
				   struct nmsg_strbuf *sb, const char *endline);

nmsg_res
_nmsg_msgmod_pres_to_payload(struct nmsg_msgmod *mod, void *cl, const char *pres);

nmsg_res
_nmsg_msgmod_pres_to_payload_load(struct nmsg_msgmod_field *field,
				  struct nmsg_msgmod_clos *clos,
				  const char *value, void *ptr, int *qptr);

nmsg_res
_nmsg_msgmod_pres_to_payload_finalize(struct nmsg_msgmod *mod, void *cl,
				      uint8_t **pbuf, size_t *sz);

nmsg_res
_nmsg_message_payload_to_json(struct nmsg_message *msg, char **json);

nmsg_res
_nmsg_message_payload_to_json_load(struct nmsg_message *msg,
				   struct nmsg_msgmod_field *field, void *ptr,
				   void * /* yajl_gen */ gen);

nmsg_res
_nmsg_msgmod_json_to_message(void * /* yajl_val */ val,
			     struct nmsg_message *msg);

nmsg_res
_nmsg_msgmod_json_to_payload_load(struct nmsg_message *msg,
				  struct nmsg_msgmod_field *field,
				  unsigned field_idx, unsigned val_idx,
				  void * /* yajl_val */ val);

nmsg_res
_nmsg_msgmod_load_field_descriptors(struct nmsg_msgmod *mod);

struct nmsg_msgmod_field *
_nmsg_msgmod_lookup_field(struct nmsg_msgmod *mod, const char *name);

/* from protobuf-c.c */
static inline size_t sizeof_elt_in_repeated_array (ProtobufCType type) {
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
  assert(0);
  return 0;
}

#endif /* NMSG_MSGMOD_TRANSPARENT_H */
