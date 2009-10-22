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

#include <nmsg.h>

nmsg_message_t
nmsg_message_init(nmsg_msgmod_t mod);

void
nmsg_message_destroy(nmsg_message_t *msg);

void
nmsg_message_clear(nmsg_message_t msg);

nmsg_message_t
nmsg_message_unpack(nmsg_msgmod_t mod, uint8_t *data, size_t len);

nmsg_message_t
nmsg_message_unpack_payload(nmsg_msgmod_t mod, Nmsg__NmsgPayload *np);

nmsg_res
nmsg_message_get_num_fields(nmsg_message_t msg, size_t *n_fields);

nmsg_res
nmsg_message_get_field_name(nmsg_message_t msg,
			    unsigned idx,
			    const char **field_name);

nmsg_res
nmsg_message_get_field_idx(nmsg_message_t msg,
			   const char *field_name,
			   unsigned *idx);

nmsg_res
nmsg_message_get_num_field_values_by_idx(nmsg_message_t msg,
					 unsigned field_idx,
					 size_t *n_field_values);

nmsg_res
nmsg_message_get_num_field_values(nmsg_message_t msg,
				  const char *field_name,
				  size_t *n_field_values);

nmsg_res
nmsg_message_get_field_type_by_idx(nmsg_message_t msg,
				   unsigned field_idx,
				   nmsg_msgmod_field_type *type);

nmsg_res
nmsg_message_get_field_type(nmsg_message_t msg,
			    const char *field_name,
			    nmsg_msgmod_field_type *type);

nmsg_res
nmsg_message_set_field_by_idx(nmsg_message_t msg, unsigned field_idx,
			      unsigned val_idx,
			      const uint8_t *data, size_t len);
nmsg_res
nmsg_message_set_field(nmsg_message_t msg, const char *field_name,
		       unsigned val_idx,
		       const uint8_t *data, size_t len);

nmsg_res
nmsg_message_get_field_by_idx(nmsg_message_t msg, unsigned field_idx,
			      unsigned val_idx,
			      uint8_t *data, size_t *len);

#endif /* NMSG_MESSAGE_H */
