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

#ifndef NMSG_ALIAS_H
#define NMSG_ALIAS_H

/*! \file nmsg/alias.h
 * \brief Nmsg payload operator and group aliasing.
 *
 * Nmsg payloads have operator and group values associated with them. These
 * values are numeric on the wire to permit extensible assignment but may be
 * aliased to presentation forms.
 */

/**
 * Alias type.
 */
typedef enum {
	nmsg_alias_operator,	/*%< operator ID -> operator name */
	nmsg_alias_group	/*%< group ID -> group name */
} nmsg_alias_e;

/**
 * Look up an alias by key.
 *
 * \param ae alias type
 * 
 * \param key numeric ID
 *
 * \return presentation form name or NULL if not found
 */
const char *
nmsg_alias_by_key(nmsg_alias_e ae, unsigned key);

/**
 * Look up an alias by name.
 *
 * \param ae alias type
 * 
 * \param value presentation form name
 *
 * \return numeric ID
 */
unsigned
nmsg_alias_by_value(nmsg_alias_e ae, const char *value);

#endif /* NMSG_ALIAS_H */
