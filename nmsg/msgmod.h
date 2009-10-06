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
 * For managing, loading, and unloading msgmods as a group, see the msgmodset.h
 * interface.
 *
 * <b>MP:</b>
 *	\li nmsg_msgmod_init() returns an opaque pointer which must be used to
 *	differentiate threads.
 */

#include <sys/types.h>
#include <stdint.h>

#include <nmsg.h>

/** Version number of the nmsg msgmod API. */
#define NMSG_MSGMOD_VERSION	5

/** \see nmsg_msgmod_init() */
typedef nmsg_res (*nmsg_msgmod_init_fp)(void **clos);

/** \see nmsg_msgmod_fini() */
typedef nmsg_res (*nmsg_msgmod_fini_fp)(void **clos);

/** \see nmsg_msgmod_msg_init() */
typedef nmsg_res (*nmsg_msgmod_msg_init_fp)(void *m);

/** \see nmsg_msgmod_msg_reset() */
typedef nmsg_res (*nmsg_msgmod_msg_reset_fp)(void *m);

/** \see nmsg_msgmod_payload_to_pres() */
typedef nmsg_res (*nmsg_msgmod_payload_to_pres_fp)(Nmsg__NmsgPayload *np,
						   char **pres,
						   const char *endline);
/** \see nmsg_msgmod_pres_to_payload() */
typedef nmsg_res (*nmsg_msgmod_pres_to_payload_fp)(void *clos, const char *pres);

/** \see nmsg_msgmod_pres_to_payload_finalize() */
typedef nmsg_res (*nmsg_msgmod_pres_to_payload_finalize_fp)(void *clos,
							    uint8_t **pbuf,
							    size_t *sz);
/** \see nmsg_msgmod_ipdg_to_payload() */
typedef nmsg_res (*nmsg_msgmod_ipdg_to_payload_fp)(void *clos,
						   const struct nmsg_ipdg *dg,
						   uint8_t **pbuf, size_t *sz);

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
 * Structure mapping protocol buffer schema fields to nmsg_msgmod_field_type
 * values for "transparent" modules.
 *
 * In order to map a protocol buffer schema into a transparent message module
 * the module must export (in a struct nmsg_msgmod) an array of these
 * structures indicating the intended nmsg field types of each field.
 */
struct nmsg_msgmod_field {
	/** Intended (nmsg) type of this protobuf field. */
	nmsg_msgmod_field_type			type;

	/** Protobuf name of the field. */
	const char				*name;

	/** \private, must be initialized to NULL */
	const ProtobufCFieldDescriptor		*descr;
};

/** Element ending a struct nmsg_msgmod_field array. */
#define NMSG_MSGMOD_FIELD_END	{ 0, NULL, NULL }

/**
 * Type of message module.
 *
 * libnmsg provides a "transparent" type of module for module developers that
 * requires only a simple structure to provide glue for a "simple" protocol
 * buffers schema (in particular, a transparent module message type schema
 * can only use fundamental protobuf data types and cannot embed other message
 * definitions). libnmsg will use generic functions to encode and decode the
 * message fields.
 *
 * "Opaque" modules must provide functions to get, set, append, etc. message
 * fields and to encode and decode the message payload.
 */
typedef enum {
	nmsg_msgmod_type_transparent,
	nmsg_msgmod_type_opaque
} nmsg_msgmod_type;

/**
 * Structure exported by message modules to implement a new message type.
 *
 * A module developer may choose to make a module "transparent" or "opaque" by
 * setting the type field to the appropriate value and setting certain fields
 * and leaving other fields unset. The transparent module interface is intended
 * for modules that do not implement IP datagram parsing and whose structure
 * can be restricted (in particular, a transparent module message type cannot
 * embed other message types). A transparent module developer must provide a
 * mapping between protobuf field types and nmsg msgmod field types and generic
 * functions will be provided to convert to and from presentation form.
 */
struct nmsg_msgmod {
	/**
	 * Module interface version.
	 * Must be set to #NMSG_MSGMOD_VERSION or the
	 * module will be rejected at load time.
	 */
	int					msgver;

	/**
	 * Module type.
	 */
	nmsg_msgmod_type			type;

	/**
	 * Vendor ID and name.
	 * Must always be <b>set</b>.
	 */
	struct nmsg_idname			vendor;

	/**
	 * Message type and name.
	 * Must always be <b>set</b>.
	 */
	struct nmsg_idname			msgtype;

	/**
	 * Module initialization function.
	 * Must be <b>unset</b> for transparent modules.
	 * May be <b>set</b> for opaque modules.
	 */
	nmsg_msgmod_init_fp			init;

	/**
	 * Module finalization function.
	 * Must be <b>unset</b> for transparent modules.
	 * May be <b>set</b> for opaque modules.
	 */
	nmsg_msgmod_fini_fp			fini;

	/**
	 * Message initialization function.
	 * Must be <b>unset</b> for transparent modules.
	 * Must be <b>set</b> for opaque modules.
	 */
	nmsg_msgmod_msg_init_fp			msg_init;

	/**
	 * Message reset function.
	 * Must be <b>unset</b> for transparent modules.
	 * Must be <b>set</b> for opaque modules.
	 */
	nmsg_msgmod_msg_reset_fp		msg_reset;

	/**
	 * Module function to convert protobuf payloads to presentation form.
	 * May be <b>set</b>.
	 *
	 * If not set for transparent modules, a generic function will be used.
	 * If not set for opaque modules, an error will be returned to the
	 * caller.
	 */
	nmsg_msgmod_payload_to_pres_fp		payload_to_pres;

	/**
	 * Module function to convert presentation form lines to NMSG
	 * payloads.
	 * May be <b>set</b>.
	 *
	 * If not set for transparent modules, a generic function will be used.
	 * If not set for opaque modules, an error will be returned to the
	 * caller.
	 */
	nmsg_msgmod_pres_to_payload_fp		pres_to_payload;

	/**
	 * Module function to finalize the conversion of presentation form lines
	 * to NMSG payloads.
	 * Must be <b>set</b> if nmsg_msgmod.pres_to_payload is set, otherwise must
	 * be <b>unset</b>.
	 */
	nmsg_msgmod_pres_to_payload_finalize_fp	pres_to_payload_finalize;

	/**
	 * Module function to convert reassembled IP datagrams to NMSG
	 * payloads.
	 * Must be <b>unset</b> for automatic modules.
	 * May be <b>set</b> for manual modules.
	 */
	nmsg_msgmod_ipdg_to_payload_fp		ipdg_to_payload;

	/**
	 * Pointer to the ProtobufCMessageDescriptor for the protocol buffer
	 * schema. This is generated by the protobuf-c compiler and usually ends
	 * in "__descriptor".
	 * Must be <b>set</b> for transparent modules.
	 * Must be <b>unset</b> for opaque modules.
	 */
	const ProtobufCMessageDescriptor	*pbdescr;

	/**
	 * Array mapping protobuf fields to nmsg types.
	 * Must be <b>set</b> for transparent modules.
	 * Must be <b>unset</b> for opaque modules.
	 */
	struct nmsg_msgmod_field		*fields;
};

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
 * Convert a message payload to presentation form.
 *
 * Msgmods are not required to implement a function to convert payload data to
 * presentation form, in which case #nmsg_res_notimpl will be returned.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[in] np nmsg payload which can be interpreted by 'mod'.
 *
 * \param[out] pres presentation form of 'np'.
 *
 * \param[in] endline string to use for line continuation.
 *
 * Returns:
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_memfail
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_msgmod_payload_to_pres(nmsg_msgmod_t mod, Nmsg__NmsgPayload *np,
			    char **pres, const char *endline);

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
 * Initialize a message.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[out] m pointer to a msgmod module-specific message structure.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_msgmod_message_init(nmsg_msgmod_t mod, void *m);

/**
 * Reset a message.
 *
 * This function should be used after the message has been serialized.
 * All resources allocated by the message will be freed and the message object
 * can be reused.
 *
 * \param[in] mod initialized msgmod.
 *
 * \param[out] m pointer to a msgmod module-specific message structure.
 */
nmsg_res
nmsg_msgmod_message_reset(nmsg_msgmod_t mod, void *m);

#endif /* NMSG_MSGMOD_H */
