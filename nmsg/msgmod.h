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

#ifndef NMSG_MSGMOD_H
#define NMSG_MSGMOD_H

/*! \file nmsg/msgmod.h
 * \brief Message modules.
 *
 * Message modules extend nmsg by allowing new message types to be implemented
 * in dynamically loaded plugins. Msgmods identify the types of messages they
 * can handle by registering a vendor ID number and a per-vendor message type
 * number with the msgmod loader. Functions for creating and interpreting nmsg
 * payloads must be provided.
 *
 * Msgmods are dynamically loaded shared objects that must provide either a
 * symbol called <tt>nmsg_msgmod_ctx</tt> of type nmsg_msgmod or a symbol called
 * <tt>nmsg_msgmod_ctx_array</tt> which will be interpreted as an array of
 * pointers to objects of type struct nmsg_msgmod. If an array is used, the array
 * must be terminated by a NULL pointer.
 *
 * The first field of the nmsg_msgmod structure is the version of the API between
 * libnmsg and the extension module; module developers should use this header
 * file for the struct nmsg_msgmod definition and assign this field the value
 * #NMSG_MSGMOD_VERSION.
 *
 * Modules must be reentrant, as exported message handling functions may be
 * called from multiple threads simultaneously.  An opaque pointer may be
 * returned by the module initialization function; this pointer will be provided
 * to module functions that require state and will be provided to the module
 * finalization function for deallocation.
 *
 * If a message schema is restricted in a certain way, a C stub consisting of
 * data definitions only can be used to interface with libnmsg.  This is called
 * a "transparent module". Transparent modules are implemented using the
 * Protobuf-C compiler.
 *
 * For an example of a transparent module, see the ISC/email message type in
 * the nmsg distribution. The file <tt>nmsg/isc/email.proto</tt> is compiled
 * with the <a href="http://code.google.com/p/protobuf-c/">Protobuf-C
 * compiler</a> into the files email.pb-c.c and email.pb-c.h. The file
 * nmsgpb_isc_email.h provides the message type number assignment and
 * nmsgpb_isc_email.c provides the C stub to interface with the msgmod.h
 * interface, which is compiled into a shared object and installed into the
 * nmsg module directory.
 *
 * <b>MP:</b>
 *	\li nmsg_msgmod_init() returns an opaque pointer which must be used to
 *	differentiate threads.
 */

#include <sys/types.h>
#include <stdint.h>

#include <nmsg.h>

/**
 * Enum mapping protocol buffer schema types to nmsg-specific types for
 * "transparent" modules.
 *
 * Protocol buffers provide basic data types on which transparent message
 * modules can build more meaningful types.
 */
typedef enum {
	/** Protobuf enum. */
	nmsg_msgmod_ft_enum,

	/** Protobuf byte array. */
	nmsg_msgmod_ft_bytes,

	/**
	 * Protobuf byte array.
	 * String should not contain newlines.
	 */
	nmsg_msgmod_ft_string,

	/**
	 * Protobuf byte array.
	 * String can contain newlines.
	 */
	nmsg_msgmod_ft_mlstring,

	/**
	 * Protobuf byte array.
	 * Length must be 4 for IPv4 addresses or 16 for IPv6 addresses.
	 */
	nmsg_msgmod_ft_ip,

	/** Protobuf uint32. */
	nmsg_msgmod_ft_uint16,

	/** Protobuf uint32. */
	nmsg_msgmod_ft_uint32,

	/** Protobuf uint64. */
	nmsg_msgmod_ft_uint64,

	/** Protobuf int32. */
	nmsg_msgmod_ft_int16,

	/** Protobuf int32. */
	nmsg_msgmod_ft_int32,

	/** Protobuf int64. */
	nmsg_msgmod_ft_int64,
} nmsg_msgmod_field_type;

/**
 * Field flag values.
 */

#define NMSG_MSGMOD_FIELD_REPEATED      0x01
#define NMSG_MSGMOD_FIELD_REQUIRED      0x02
#define NMSG_MSGMOD_FIELD_HIDDEN        0x04
#define NMSG_MSGMOD_FIELD_NOPRINT       0x08

/**
 * Initialize a message module.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[out] clos opaque pointer specific to this instantiation of the module.
 *	This pointer must be supplied to nmsg_msgmod functions taking a 'clos'
 *	parameter.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_memfail
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_msgmod_init(nmsg_msgmod_t mod, void **clos);

/**
 * Finalize a mesage module.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[in] clos opaque pointer returned by the module initialization
 *	function.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_msgmod_fini(nmsg_msgmod_t mod, void **clos);

/**
 * Convert a presentation format line to an nmsg payload.
 * Since the presentation format stream is line-delimited, not every line
 * will necessarily result in a serialized message.
 *
 * When #nmsg_res_pbuf_ready is returned, the nmsg_msgmod_pres_to_payload_finalize()
 * function should be used to obtain the serialized payload.
 *
 * Msgmods are not required to implement a function to convert presentation form
 * data to payloads, in which case #nmsg_res_notimpl will be returned.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[in] clos opaque pointer returned by the module initialization
 *	function.
 *
 * \param[in] pres line of presentation form input of the type handled by 'mod'.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_memfail
 * \return #nmsg_res_notimpl
 * \return #nmsg_res_parse_error
 * \return #nmsg_res_pbuf_ready
 */
nmsg_res
nmsg_msgmod_pres_to_payload(nmsg_msgmod_t mod, void *clos, const char *pres);

/**
 * After a call to nmsg_msgmod_pres_to_payload() returns #nmsg_res_pbuf_ready, this
 * function will return the serialized payload. The caller is responsible for
 * freeing the payload returned.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[in] clos opaque pointer returned by the module initialization
 *	function.
 *
 * \param[out] pbuf serialized payload.
 *
 * \param[out] sz length of the serialized payload.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_memfail
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_msgmod_pres_to_payload_finalize(nmsg_msgmod_t mod, void *clos, uint8_t **pbuf,
				     size_t *sz);

/**
 * Convert an IP datagram to an nmsg payload.
 *
 * Msgmods are not required to implement a function to convert IP datagrams to
 * payloads, in which case #nmsg_res_notimpl will be returned.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[in] clos opaque pointer returned by the module initialization
 *	function.
 *
 * \param[in] dg filled nmsg_ipdg structure.
 *
 * \param[out] pbuf serialized payload.
 *
 * \param[out] sz length of the serialized payload.
 *
 * \return #nmsg_res_parse_error
 * \return #nmsg_res_pbuf_ready
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_msgmod_ipdg_to_payload(nmsg_msgmod_t mod, void *clos,
			    const struct nmsg_ipdg *dg,
			    uint8_t **pbuf, size_t *sz);

/**
 * Determine which nmsg_msgmod is responsible for a given vid/msgtype tuple,
 * if any.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \param[in] msgtype numeric message type.
 *
 * \return The nmsg_msgmod responsible for handling the given vid/msgtype tuple,
 *	if such a module has been loaded into the set, or NULL otherwise.
 */
nmsg_msgmod_t
nmsg_msgmod_lookup(unsigned vid, unsigned msgtype);

/**
 * Determine which nmsg_msgmod is responsible for a given vid/msgtype tuple,
 * if any. This function looks up the vid and msgtype by name.
 *
 * \param[in] vname vendor name.
 *
 * \param[in] mname message type name.
 *
 * \return The nmsg_msgmod responsible for handling the given vid/msgtype tuple,
 *	if such a module has been loaded into the set, or NULL otherwise.
 */
nmsg_msgmod_t
nmsg_msgmod_lookup_byname(const char *vname, const char *mname);

/**
 * Convert the human-readable name of a message type to a message type ID.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \param[in] mname message type name.
 *
 * \return A numeric message type ID. By convention, 0 is used to indicate an
 *	unknown message type.
 */
unsigned
nmsg_msgmod_mname_to_msgtype(unsigned vid, const char *mname);

/**
 * Convert a vendor ID / message type ID tuple to the human-readable form
 * of the message type.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \param[in] msgtype numeric message type.
 *
 * \return A human-readable message type name. NULL is returned if the vendor ID
 *	or message type is unknown.
 */
const char *
nmsg_msgmod_msgtype_to_mname(unsigned vid, unsigned msgtype);

/**
 * Convert a numeric vendor ID to its human-readable name.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \return A human-readable vendor name. NULL is returned if the vendor ID is
 *	unknown.
 */
const char *
nmsg_msgmod_vid_to_vname(unsigned vid);

/**
 * Convert a human-readable vendor name to its numeric ID.
 *
 * \param[in] vname vendor name.
 *
 * \return A numeric vendor ID. By convention, 0 is used to indicate an unknown
 *	vendor ID.
 */
unsigned
nmsg_msgmod_vname_to_vid(const char *vname);

/**
 * Return the maximum vendor ID.
 *
 * \return maximum vendor ID.
 */
unsigned
nmsg_msgmod_get_max_vid(void);

/**
 * Return the maximum message type registered to a vendor ID.
 *
 * \param[in] vid numeric vendor ID.
 *
 * \return maximum message type.
 */
unsigned
nmsg_msgmod_get_max_msgtype(unsigned vid);

#endif /* NMSG_MSGMOD_H */
