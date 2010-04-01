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

#ifndef NMSG_MESSAGE_H
#define NMSG_MESSAGE_H

/*! \file nmsg/message.h
 * \brief Create, load, inspect, and manipulate message objects. Message
 * objects are proxy objects that bind together the in-memory and wire format
 * representations of NMSG payloads. Deserialization of the wire format
 * representation will occur implicitly and only when needed.
 *
 * There are a number of functions for inspecting and modifying the metadata
 * associated with an NMSG payload message object:
 *
 * nmsg_message_get_vid()
 * nmsg_message_get_msgtype()
 * nmsg_message_get_time() / nmsg_message_set_time()
 * nmsg_message_get_source() / nmsg_message_set_source()
 * nmsg_message_get_operator() / nmsg_message_set_operator()
 * nmsg_message_get_source() / nmsg_message_set_source()
 *
 * For transparent messages, the underlying fields can be inspected or
 * modified using the following functions. Fields can either be specified by
 * name or by index.
 *
 * nmsg_message_set_field() / nmsg_message_set_field_by_idx()
 * nmsg_message_get_field() / nmsg_message_get_field_by_idx()
 * nmsg_message_get_field_idx()
 * nmsg_message_get_field_name()
 * nmsg_message_get_field_flags() / nmsg_message_get_field_flags_by_idx()
 * nmsg_message_get_field_type() / nmsg_message_get_field_type_by_idx()
 * nmsg_message_get_num_fields
 *
 * For enum field types, there are several helper functions for converting
 * between the presentation and numeric forms of enum values:
 *
 * nmsg_message_enum_name_to_value() / nmsg_message_enum_name_to_value_by_idx()
 * nmsg_message_enum_value_to_name() / nmsg_message_enum_value_to_name_by_idx()
 */

#include <nmsg.h>

/**
 * Initialize a new, empty message object of a particular type.
 *
 * \param[in] mod Message module corresponding to the type of message to
 *	create.
 *
 * \return New message object or NULL on error.
 */
nmsg_message_t
nmsg_message_init(nmsg_msgmod_t mod);

/**
 * Destroy a message object and deallocate any resources associated with it.
 *
 * \param[in] msg Pointer to message object.
 */
void
nmsg_message_destroy(nmsg_message_t *msg);

/**
 * Convert a message object to presentation format.
 *
 * \param[in] msg Message object.
 * \param[out] pres Location to store malloc() allocated presentation format
 *	string.
 * \param[in] endline Character string to use to delimit lines.
 *
 * \return #nmsg_res_success if presentation format string was successfully
 *	rendered, non-success otherwise.
 */
nmsg_res
nmsg_message_to_pres(nmsg_message_t msg, char **pres, const char *endline);

/**
 * Return the message module object associated with a message object.
 */
nmsg_msgmod_t
nmsg_message_get_msgmod(nmsg_message_t msg);

/**
 * Return the vendor ID of a message object.
 */
int32_t
nmsg_message_get_vid(nmsg_message_t msg);

/**
 * Return the message type of a message object.
 */
int32_t
nmsg_message_get_msgtype(nmsg_message_t msg);

/**
 * WARNING: experts only.
 *
 * Return the protobuf message object underlying (some) message objects.
 */
const void *
nmsg_message_get_payload(nmsg_message_t msg);

/**
 * Get the timestamp of a message object.
 *
 * \param[in] msg Message object.
 * \param[out] ts Pointer to timespec instance.
 */
void
nmsg_message_get_time(nmsg_message_t msg, struct timespec *ts);

/**
 * Set the timestamp of a message object.
 *
 * \param[in] msg Message object.
 * \param[in] ts Pointer to timespec instance. If NULL, set the timestamp to
 *	the current time.
 */
void
nmsg_message_set_time(nmsg_message_t msg, const struct timespec *ts);

/**
 * Get the source ID of a message object.  0 indicates that the source ID
 * field was not set.
 */
uint32_t
nmsg_message_get_source(nmsg_message_t msg);

/**
 * Get the operator of a message object.  0 indicates that the operator ID
 * field was not set.
 */
uint32_t
nmsg_message_get_operator(nmsg_message_t msg);

/**
 * Get the group of a message object.  0 indicates that the group ID
 * field was not set.
 */
uint32_t
nmsg_message_get_group(nmsg_message_t msg);

/**
 * Set the source ID of a message object.  0 will remove the source ID field.
 */
void
nmsg_message_set_source(nmsg_message_t msg, uint32_t source);

/**
 * Set the operator of a message object.  0 will remove the operator field.
 */
void
nmsg_message_set_operator(nmsg_message_t msg, uint32_t operator_);

/**
 * Set the group of a message object.  0 will remove the group field.
 */
void
nmsg_message_set_group(nmsg_message_t msg, uint32_t group);

/**
 * Get the value of a field. Note that the data pointer returned by this
 * function is not a copy, and is valid as long as the message object is
 * valid.
 *
 * \param[in] msg Message object.
 * \param[in] field_name Name of the field.
 * \param[in] val_idx Index of the field value to retrieve. Singleton fields
 *	have only a single value index, 0.
 * \param[out] data Location to store a pointer to the field value.
 * \param[out] len Length of the field value in bytes. May be NULL.
 */
nmsg_res
nmsg_message_get_field(nmsg_message_t msg,
		       const char *field_name,
		       unsigned val_idx,
		       void **data,
		       size_t *len);

/**
 * Get the value of a field. Field specified by index.
 * \see nmsg_message_get_field()
 */
nmsg_res
nmsg_message_get_field_by_idx(nmsg_message_t msg,
			      unsigned field_idx,
			      unsigned val_idx,
			      void **data,
			      size_t *len);

/**
 * Get the field index of a named field.
 *
 * \param[in] msg Message object.
 * \param[in] field_name Name of the field.
 * \param[out] idx Location to store field index value.
 */
nmsg_res
nmsg_message_get_field_idx(nmsg_message_t msg,
			   const char *field_name,
			   unsigned *idx);

/**
 * Get the name of a field specified by index.
 *
 * \param[in] msg Message object.
 * \param[in] field_idx Index of the field.
 * \param[out] field_name Location to store field name.
 */
nmsg_res
nmsg_message_get_field_name(nmsg_message_t msg,
			    unsigned field_idx,
			    const char **field_name);

/**
 * Get the flags associated with a field. See msgmod.h for NMSG_MSGMOD_FIELD_*
 * definitions.
 *
 * \param[in] msg Message object.
 * \param[in] field_name Name of the field.
 * \param[out] flags Location to store flags value.
 */
nmsg_res
nmsg_message_get_field_flags(nmsg_message_t msg,
			     const char *field_name,
			     unsigned *flags);

/**
 * Get the flags associated with a field. Field specified by index.
 * \see nmsg_message_get_field_flags()
 */
nmsg_res
nmsg_message_get_field_flags_by_idx(nmsg_message_t msg,
				    unsigned field_idx,
				    unsigned *flags);

/**
 * Get the type of a field.
 *
 * \param[in] msg Message object.
 * \param[in] field_name Name of the field.
 * \param[out] type Location to store field type value.
 */
nmsg_res
nmsg_message_get_field_type(nmsg_message_t msg,
			    const char *field_name,
			    nmsg_msgmod_field_type *type);

/**
 * Get the type of af ield. Field specified by index.
 * \see nmsg_message_get_field_type()
 */
nmsg_res
nmsg_message_get_field_type_by_idx(nmsg_message_t msg,
				   unsigned field_idx,
				   nmsg_msgmod_field_type *type);

/**
 * Get the total number of possible fields that a message can contain.
 *
 * \param[in] msg Message object.
 * \param[out] n_fields Location to store number of fields.
 */
nmsg_res
nmsg_message_get_num_fields(nmsg_message_t msg, size_t *n_fields);

/**
 * Set a field to the specified value. Data is copied from the caller's
 * buffer.
 *
 * \param[in] msg Message object.
 * \param[in] field_name Name of the field.
 * \param[in] val_idx Index of the field value to be set. Must be zero if the
 *	field is not a repeated field.
 * \param[in] data Data buffer containing the value.
 * \param[in] len Length of data buffer.
 */
nmsg_res
nmsg_message_set_field(nmsg_message_t msg,
		       const char *field_name,
		       unsigned val_idx,
		       const uint8_t *data,
		       size_t len);

/**
 * Set a field to the specified value. Field specified by index.
 * \see nmsg_message_set_field()
 */
nmsg_res
nmsg_message_set_field_by_idx(nmsg_message_t msg,
			      unsigned field_idx,
			      unsigned val_idx,
			      const uint8_t *data,
			      size_t len);

/**
 * Convert an enum name to a numeric value.
 *
 * \param[in] msg Message object.
 * \param[in] field_name Name of the field.
 * \param[in] name Name of the enum.
 * \param[out] value Location to store numeric enum value.
 */
nmsg_res
nmsg_message_enum_name_to_value(nmsg_message_t msg, const char *field_name,
				const char *name, unsigned *value);

/**
 * Convert an enum name to a numeric value. Field specified by index.
 * \see nmsg_message_enum_name_to_value()
 */
nmsg_res
nmsg_message_enum_name_to_value_by_idx(nmsg_message_t msg, unsigned field_idx,
				       const char *name, unsigned *value);

/**
 * Convert a numeric enum value to a symbolic name.
 *
 * \param[in] msg Message object.
 * \param[in] field_name Name of the field.
 * \param[in] value Numeric enum value.
 * \param[out] name Location to store symbolic enum name.
 */
nmsg_res
nmsg_message_enum_value_to_name(nmsg_message_t msg, const char *field_name,
				unsigned value, const char **name);

/**
 * Convert a numeric enum value to a symoblic name. Field specified by index.
 * \see nmsg_message_enum_value_to_name()
 */
nmsg_res
nmsg_message_enum_value_to_name_by_idx(nmsg_message_t msg, unsigned field_idx,
				       unsigned value, const char **name);

#endif /* NMSG_MESSAGE_H */
