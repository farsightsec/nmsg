/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#ifndef NMSG_PBMODSET_H
#define NMSG_PBMODSET_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/pbmodset.h
 * \brief Protocol buffer module sets.
 *
 * This module provides a layer of abstraction for dealing with a
 * collection of protocol buffer modules. Since nmsg can extended at
 * runtime to handle new payload types, a way to manage the installed set
 * of pbmods is needed.
 *
 * nmsg clients that need to call any of the per-module methods provided by
 * the pbmod interface should first obtain a module handle using
 * nmsg_pbmodset_lookup().
 *
 * Symbolic vendor and message type names can be converted to the numeric
 * values required by the nmsg_pbmodset_lookup() function using the
 * nmsg_pbmodset_mname_to_msgtype() and nmsg_pbmodet_vname_to_vid()
 * functions.
 *
 * \li MP:
 *	A group of threads can share a single pbmodset instance.
 */

/***
 *** Imports
 ***/

#include <nmsg.h>

/***
 *** Functions
 ***/

nmsg_pbmodset
nmsg_pbmodset_init(const char *path, int debug);
/*%<
 * Initialize a collection of pbmods stored in a directory.
 *
 * Requires:
 *
 * \li	'path' is a filesystem directory containing pbmods whose filenames
 *	begin with "pbnmsg_" and end with ".so".
 *
 * \li  'debug' is the debugging level. Values larger than zero will cause
 *      information useful for debugging allocations to be logged.
 *
 * Returns:
 *
 * \li  An opaque pointer that is NULL on failure or non-NULL on success.
 */

void
nmsg_pbmodset_destroy(nmsg_pbmodset *ms);
/*%<
 * Destroy resources allocated by a pbmodset.
 *
 * Requires:
 *
 * \li	'*fma' is a valid pointer to an nmsg_pbmodset object.
 *
 * Ensures:
 *
 * \li	'fma' will be NULL on return, and all modules dynamically loaded by
 *	the corresponding call to nmsg_pbmodset_init() will be released.
 */

nmsg_pbmod
nmsg_pbmodset_lookup(nmsg_pbmodset ms, unsigned vid, unsigned msgtype);
/*%<
 * Determine which nmsg_pbmod is responsible for a given vid/msgtype tuple,
 * if any.
 *
 * Requires:
 *
 * \li	'ms' is a valid nmsg_pbmodset object.
 *
 * \li	'vid' is a numeric vendor ID.
 *
 * \li	'msgtype' is a numeric message type.
 *
 * Returns:
 *
 * \li	The nmsg_pbmod responsible for handling the given vid/msgtype
 *	tuple, if such a module has been loaded into the set, or NULL
 *	otherwise.
 */

nmsg_pbmod
nmsg_pbmodset_lookup_byname(nmsg_pbmodset ms, const char *vname,
			    const char *mname);
/*%<
 * Determine which nmsg_pbmod is responsible for a given vid/msgtype tuple,
 * if any. This function looks up the vid and msgtype by name.
 *
 * Requires:
 *
 * \li	'ms' is a valid nmsg_pbmodset object.
 *
 * \li	'vname' is the human-readable name of a vendor.
 *
 * \li	'mname' is the human-readable name of a message type.
 *
 * Returns:
 *
 * \li	The nmsg_pbmod responsible for handling the given vid/msgtype
 *	tuple, if such a module has been loaded into the set, or NULL
 *	otherwise.
 */

unsigned
nmsg_pbmodset_mname_to_msgtype(nmsg_pbmodset ms, unsigned vid,
			       const char *mname);
/*%<
 * Convert the human-readable name of a message type to a message type ID.
 *
 * Requires:
 *
 * \li	'ms' is a valid nmsg_pbmodset object.
 *
 * \li	'vid' is a numeric vendor ID.
 *
 * \li	'mname' is the human-readable name of a message type.
 *
 * Returns:
 *
 * \li	A numeric message type ID. By convention, 0 is used to indicate an
 *	unknown message type.
 */

const char *
nmsg_pbmodset_msgtype_to_mname(nmsg_pbmodset ms, unsigned vid,
			       unsigned msgtype);
/*%<
 * Convert a vendor ID / message type ID tuple to the human-readable form
 * of the message type.
 *
 * Requires:
 *
 * \li	'ms' is a valid nmsg_pbmodset object.
 *
 * \li	'vid' is a numeric vendor ID.
 *
 * \li	'msgtype' is a numeric message type.
 *
 * Returns:
 *
 * \li	A human-readable message type name. NULL is returned if the vendor
 *	ID or message type is unknown.
 */

const char *
nmsg_pbmodset_vid_to_vname(nmsg_pbmodset ms, unsigned vid);
/*%<
 * Convert a numeric vendor ID to its human-readable name.
 *
 * Requires:
 *
 * \li	'ms' is a valid nmsg_pbmodset object.
 *
 * \li	'vid' is a numeric vendor ID.
 *
 * Returns:
 *
 * \li	A human-readable vendor name. NULL is returned if the vendor ID is
 *	unknown.
 */

unsigned
nmsg_pbmodset_vname_to_vid(nmsg_pbmodset ms, const char *vname);
/*%<
 * Convert a human-readable vendor name to its numeric ID.
 *
 *
 * Requires:
 *
 * \li	'ms' is a valid nmsg_pbmodset object.
 *
 * \li	'vname' is the human-readable name of a vendor.
 *
 * Returns:
 *
 * \li	A numeric vendor ID. By convention, 0 is used to indicate an
 *	unknown vendor ID.
 */

#endif /* NMSG_PBMODSET_H */
