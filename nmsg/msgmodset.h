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

#ifndef NMSG_MSGMODSET_H
#define NMSG_MSGMODSET_H

/*! \file nmsg/msgmodset.h
 * \brief Message module sets.
 *
 * This module provides a layer of abstraction for dealing with a collection of
 * message modules. Since nmsg can be extended at runtime to handle new payload
 * types, a way to manage the loaded set of msgmods is needed.
 *
 * nmsg clients that need to call any of the per-module methods provided by
 * the msgmod.h interface should first obtain a module handle using
 * nmsg_msgmodset_lookup() or nmsg_msgmodset_lookup_byname().
 *
 * Symbolic vendor and message type names can be converted to numeric values
 * using the nmsg_msgmodset_mname_to_msgtype() and nmsg_msgmodset_vname_to_vid()
 * functions. Numeric vendor IDs and message types can be converted to symbolic
 * names using the nmsg_msgmodset_vid_to_vname() and
 * nmsg_msgmodset_msgtype_to_mname() functions.
 *
 * <b>MP:</b>
 *	\li A group of threads can share a single msgmodset instance.
 */

#include <nmsg.h>

/**
 * Initialize a collection of msgmods stored in a directory.
 *
 * \param[in] path filesystem directory containing message modules whose
 *	filenames begin with "nmsg_msg_" and end with ".so". May be NULL to
 *	search the default directory.
 *
 * \param[in] debug debugging level. Values larger than zero will cause
 *	information useful for debugging allocations to be logged.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_msgmodset_t
nmsg_msgmodset_init(const char *path, int debug);

/**
 * Destroy resources allocated by a msgmodset.
 *
 * All dynamically loaded modules loaded by the corresponding call to
 * nmsg_msgmodset_init() will be unloaded.
 *
 * \param[in] ms pointer to an nmsg_msgmodset object.
 */
void
nmsg_msgmodset_destroy(nmsg_msgmodset_t *ms);

/**
 * Determine which nmsg_msgmod is responsible for a given vid/msgtype tuple,
 * if any.
 *
 * \param[in] ms nmsg_msgmodset object.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \param[in] msgtype numeric message type.
 *
 * \return The nmsg_msgmod responsible for handling the given vid/msgtype tuple,
 *	if such a module has been loaded into the set, or NULL otherwise.
 */
nmsg_msgmod_t
nmsg_msgmodset_lookup(nmsg_msgmodset_t ms, unsigned vid, unsigned msgtype);

/**
 * Determine which nmsg_msgmod is responsible for a given vid/msgtype tuple,
 * if any. This function looks up the vid and msgtype by name.
 *
 * \param[in] ms nmsg_msgmodset object.
 *
 * \param[in] vname vendor name.
 *
 * \param[in] mname message type name.
 *
 * \return The nmsg_msgmod responsible for handling the given vid/msgtype tuple,
 *	if such a module has been loaded into the set, or NULL otherwise.
 */
nmsg_msgmod_t
nmsg_msgmodset_lookup_byname(nmsg_msgmodset_t ms, const char *vname,
			     const char *mname);

/**
 * Convert the human-readable name of a message type to a message type ID.
 *
 * \param[in] ms nmsg_msgmodset object.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \param[in] mname message type name.
 *
 * \return A numeric message type ID. By convention, 0 is used to indicate an
 *	unknown message type.
 */
unsigned
nmsg_msgmodset_mname_to_msgtype(nmsg_msgmodset_t ms, unsigned vid,
				const char *mname);

/**
 * Convert a vendor ID / message type ID tuple to the human-readable form
 * of the message type.
 *
 * \param[in] ms nmsg_msgmodset object.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \param[in] msgtype numeric message type.
 *
 * \return A human-readable message type name. NULL is returned if the vendor ID
 *	or message type is unknown.
 */
const char *
nmsg_msgmodset_msgtype_to_mname(nmsg_msgmodset_t ms, unsigned vid,
				unsigned msgtype);

/**
 * Convert a numeric vendor ID to its human-readable name.
 *
 * \param[in] ms nmsg_msgmodset object.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \return A human-readable vendor name. NULL is returned if the vendor ID is
 *	unknown.
 */
const char *
nmsg_msgmodset_vid_to_vname(nmsg_msgmodset_t ms, unsigned vid);

/**
 * Convert a human-readable vendor name to its numeric ID.
 *
 * \param[in] ms nmsg_msgmodset object.
 *
 * \param[in] vname vendor name.
 *
 * \return A numeric vendor ID. By convention, 0 is used to indicate an unknown
 *	vendor ID.
 */
unsigned
nmsg_msgmodset_vname_to_vid(nmsg_msgmodset_t ms, const char *vname);

/**
 * Return the maximum vendor ID.
 *
 * \param[in] ms nmsg_msgmodset object.
 *
 * \return maximum vendor ID.
 */
unsigned
nmsg_msgmodset_get_max_vid(nmsg_msgmodset_t ms);

/**
 * Return the maximum message type registered to a vendor ID.
 *
 * \param[in] ms nmsg_msgmodset object.
 * \param[in] vid numeric vendor ID.
 *
 * \return maximum message type.
 */
unsigned
nmsg_msgmodset_get_max_msgtype(nmsg_msgmodset_t ms, unsigned vid);

#endif /* NMSG_MSGMODSET_H */
