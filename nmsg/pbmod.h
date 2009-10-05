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

#ifndef NMSG_PBMOD_H
#define NMSG_PBMOD_H

/*! \file nmsg/pbmod.h
 * \brief Protocol buffer modules.
 *
 * Protocol buffer modules extend nmsg by allowing new message types to be
 * implemented in dynamically loaded plugins. Pbmods identify the types of
 * messages they can handle by registering a vendor ID number and a per-vendor
 * message type number with the pbmod loader. Functions for creating and
 * interpreting nmsg payloads must be provided.
 *
 * Pbmods are dynamically loaded shared objects that must provide either a
 * symbol called <tt>nmsg_pbmod_ctx</tt> of type nmsg_pbmod or a symbol called
 * <tt>nmsg_pbmod_ctx_array</tt> which will be interpreted as an array of
 * pointers to objects of type struct nmsg_pbmod. If an array is used, the array
 * must be terminated by a NULL pointer.
 *
 * The first field of the nmsg_pbmod structure is the version of the API between
 * libnmsg and the extension module; module developers should use this header
 * file for the struct nmsg_pbmod definition and assign this field the value
 * #NMSG_PBMOD_VERSION.
 *
 * Modules must be reentrant, as exported message handling functions may be
 * called from multiple threads simultaneously.  An opaque pointer may be
 * returned by the module initialization function; this pointer will be provided
 * to module functions that require state and will be provided to the module
 * finalization function for deallocation.
 *
 * If a protocol buffer message schema is restricted in a certain way, a C stub
 * consisting of data definitions only can be used to interface with libnmsg.
 * This is called an "automatic module".
 *
 * For an example of an automatic module, see the ISC/email message type in the
 * nmsg distribution. The file <tt>nmsg/isc/email.proto</tt> is compiled with
 * the <a href="http://code.google.com/p/protobuf-c/">Protobuf-C compiler</a>
 * into the files email.pb-c.c and email.pb-c.h. The file nmsgpb_isc_email.h
 * provides the message type number assignment and nmsgpb_isc_email.c provides
 * the C stub to interface with the pbmod.h interface, which is compiled into a
 * shared object and installed into the nmsg module directory.
 *
 * For managing, loading, and unloading pbmods as a group, see the pbmodset.h
 * interface.
 *
 * <b>MP:</b>
 *	\li nmsg_pbmod_init() returns an opaque pointer which must be used to
 *	differentiate threads.
 */

#include <sys/types.h>
#include <stdint.h>

#include <nmsg.h>

/** Version number of the nmsg pbmod API. */
#define NMSG_PBMOD_VERSION	5

/** \see nmsg_pbmod_init() */
typedef nmsg_res (*nmsg_pbmod_init_fp)(void **clos);

/** \see nmsg_pbmod_fini() */
typedef nmsg_res (*nmsg_pbmod_fini_fp)(void **clos);

/** \see nmsg_pbmod_pbuf_to_pres() */
typedef nmsg_res (*nmsg_pbmod_pbuf_to_pres_fp)(Nmsg__NmsgPayload *np,
					       char **pres,
					       const char *endline);
/** \see nmsg_pbmod_pres_to_pbuf() */
typedef nmsg_res (*nmsg_pbmod_pres_to_pbuf_fp)(void *clos, const char *pres);

/** \see nmsg_pbmod_pres_to_pbuf_finalize() */
typedef nmsg_res (*nmsg_pbmod_pres_to_pbuf_finalize_fp)(void *clos,
							uint8_t **pbuf,
							size_t *sz);
/** \see nmsg_pbmod_ipdg_to_pbuf() */
typedef nmsg_res (*nmsg_pbmod_ipdg_to_pbuf_fp)(void *clos,
					       const struct nmsg_ipdg *dg,
					       uint8_t **pbuf, size_t *sz);

/**
 * Enum mapping protocol buffer schema types to nmsg-specific types for
 * "automatic" modules.
 *
 * Protocol buffers provide basic data types on which automatic nmsgpb modules
 * can build more meaningful types.
 */
typedef enum {
	/** Protobuf enum. */
	nmsg_pbmod_ft_enum,

	/**
	 * Protobuf byte array.
	 * String should not contain newlines.
	 */
	nmsg_pbmod_ft_string,

	/**
	 * Protobuf byte array.
	 * String can contain newlines.
	 */
	nmsg_pbmod_ft_mlstring,

	/**
	 * Protobuf byte array.
	 * Length must be 4 for IPv4 addresses or 16 for IPv6 addresses.
	 */
	nmsg_pbmod_ft_ip,

	/** Protobuf uint32. */
	nmsg_pbmod_ft_uint16,

	/** Protobuf uint32. */
	nmsg_pbmod_ft_uint32,

	/** Protobuf uint64. */
	nmsg_pbmod_ft_uint64,

	/** Protobuf int32. */
	nmsg_pbmod_ft_int16,

	/** Protobuf int32. */
	nmsg_pbmod_ft_int32,

	/** Protobuf int64. */
	nmsg_pbmod_ft_int64,
} nmsg_pbmod_field_type;

/**
 * Structure mapping protocol buffer schema fields to nmsg_pbmod_field_type
 * values for "automatic" modules.
 *
 * In order to map a protocol buffer schema into an automatic nmsgpb module the
 * module must export (in a struct nmsg_pbmod) an array of these structures
 * indicating the intended nmsg field types of each field.
 */
struct nmsg_pbmod_field {
	/** Intended (nmsg) type of this protobuf field. */
	nmsg_pbmod_field_type			type;

	/** Protobuf name of the field. */
	const char				*name;

	/** \private */
	const ProtobufCFieldDescriptor		*descr;
};

/** Element ending a struct nmsg_pbmod_field array. */
#define NMSG_PBMOD_FIELD_END	{ 0, NULL, NULL }

/**
 * Structure exported by nmsg protocol buffer modules to implement a new message
 * type.
 *
 * A module developer may choose to make a module "automatic" or "manual" by
 * setting certain fields and leaving other fields unset. The automatic module
 * interface is intended for modules that do not implement IP datagram parsing
 * and whose structure can be restricted (in particular, an automatic module
 * message type cannot embed other message types). An automatic module developer
 * must provide a mapping between protobuf field types and nmsg pbmod field
 * types and generic functions will be provided to convert to and from
 * presentation form.
 */
struct nmsg_pbmod {
	/**
	 * Module interface version.
	 * Must be set to #NMSG_PBMOD_VERSION or the
	 * module will be rejected at load time.
	 */
	int					pbmver;

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
	 * Must be <b>unset</b> for automatic modules.
	 * Must be <b>set</b> for manual modules.
	 */
	nmsg_pbmod_init_fp			init;

	/**
	 * Module finalization function.
	 * Must be <b>unset</b> for automatic modules.
	 * Must be <b>set</b> for manual modules.
	 */
	nmsg_pbmod_fini_fp			fini;

	/**
	 * Module function to convert protobuf payloads to presentation form.
	 * Must be <b>unset</b> for automatic modules.
	 * Must be <b>set</b> for manual modules.
	 */
	nmsg_pbmod_pbuf_to_pres_fp		pbuf_to_pres;

	/**
	 * Module function to convert presentation form lines to protobuf
	 * payloads.
	 * Must be <b>unset</b> for automatic modules.
	 * May be <b>set</b> for manual modules.
	 */
	nmsg_pbmod_pres_to_pbuf_fp		pres_to_pbuf;

	/**
	 * Module function to finalize the conversion of presentation form lines
	 * to protobuf payloads.
	 * Must be <b>unset</b> for automatic modules.
	 * May be <b>set</b> for manual modules.
	 * Must be <b>set</b> if nmsg_pbmod.pres_to_pbuf is set.
	 */
	nmsg_pbmod_pres_to_pbuf_finalize_fp	pres_to_pbuf_finalize;

	/**
	 * Module function to convert reassembled IP datagrams to protobuf
	 * payloads.
	 * Must be <b>unset</b> for automatic modules.
	 * May be <b>set</b> for manual modules.
	 */
	nmsg_pbmod_ipdg_to_pbuf_fp		ipdg_to_pbuf;

	/**
	 * Pointer to the ProtobufCMessageDescriptor for the protocol buffer
	 * schema. This is generated by the protobuf-c compiler and usually ends
	 * in "__descriptor".
	 * Must be <b>set</b> for automatic modules.
	 * Must be <b>set</b> for manual modules.
	 */
	const ProtobufCMessageDescriptor	*pbdescr;

	/**
	 * ProtobufCFieldDescriptor array for the protocol buffer schema. This
	 * is generated by the protobuf-c compiler and usually ends in
	 * "__field_descriptors".
	 * Must be <b>set</b> for automatic modules.
	 * Must be <b>unset</b> for manual modules.
	 */
	const ProtobufCFieldDescriptor		*pbfields;

	/**
	 * Array mapping protobuf fields to nmsg types.
	 * Must be <b>set</b> for automatic modules.
	 * Must be <b>unset</b> for manual modules.
	 */
	struct nmsg_pbmod_field			*fields;
};

/**
 * Initialize a protocol buffer module.
 *
 * \param[in] mod initialized pbmod.
 *
 * \param[out] clos opaque pointer specific to this instantiation of the module.
 *	This pointer must be supplied to nmsg_pbmod functions taking a 'clos'
 *	parameter.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_memfail
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_pbmod_init(nmsg_pbmod_t mod, void **clos);

/**
 * Finalize a protocol buffer module.
 *
 * \param[in] mod initialized pbmod.
 *
 * \param[in] clos opaque pointer returned by the module initialization
 *	function.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_pbmod_fini(nmsg_pbmod_t mod, void **clos);

/**
 * Convert a protocol buffer nmsg payload to presentation form.
 *
 * Pbmods are not required to implement a function to convert payload data to
 * presentation form, in which case #nmsg_res_notimpl will be returned.
 *
 * \param[in] mod initialized pbmod.
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
nmsg_pbmod_pbuf_to_pres(nmsg_pbmod_t mod, Nmsg__NmsgPayload *np, char **pres,
			const char *endline);

/**
 * Convert a presentation format line to a protocol buffer nmsg payload.
 * Since the presentation format stream is line-delimited, not every line
 * will necessarily result in a serialized pbuf.
 *
 * When #nmsg_res_pbuf_ready is returned, the nmsg_pbmod_pres_to_pbuf_finalize()
 * function should be used to obtain the serialized pbuf.
 *
 * Pbmods are not required to implement a function to convert presentation form
 * data to payloads, in which case #nmsg_res_notimpl will be returned.
 *
 * \param[in] mod initialized pbmod.
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
nmsg_pbmod_pres_to_pbuf(nmsg_pbmod_t mod, void *clos, const char *pres);

/**
 * After a call to nmsg_pbmod_pres_to_pbuf() returns #nmsg_res_pbuf_ready, this
 * function will return the serialized pbuf. The caller is responsible for
 * freeing the payload returned.
 *
 * \param[in] mod initialized pbmod.
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
nmsg_pbmod_pres_to_pbuf_finalize(nmsg_pbmod_t mod, void *clos, uint8_t **pbuf,
				 size_t *sz);

/**
 * Convert an IP datagram to a protocol buffer nmsg payload.
 *
 * Pbmods are not required to implement a function to convert IP datagrams to
 * payloads, in which case #nmsg_res_notimpl will be returned.
 *
 * \param[in] mod initialized pbmod.
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
nmsg_pbmod_ipdg_to_pbuf(nmsg_pbmod_t mod, void *clos,
			const struct nmsg_ipdg *dg,
			uint8_t **pbuf, size_t *sz);

/**
 * Initialize a message. This function is only implemented for automatic
 * modules.
 *
 * \param[in] mod initialized pbmod.
 *
 * \param[out] m pointer to a pbnmsg module-specific message structure.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_notimpl
 */
nmsg_res
nmsg_pbmod_message_init(nmsg_pbmod_t mod, void *m);

/**
 * Reset a message. This function is only implemented for automatic
 * modules.
 *
 * This function should be used after the message has been serialized.
 * All message field quantifiers will be reset and fields allocated with
 * malloc will be freed.
 *
 * \param[in] mod initialized automatic pbmod.
 *
 * \param[out] m pointer to a pbnmsg module-specific message structure.
 */
nmsg_res
nmsg_pbmod_message_reset(nmsg_pbmod_t mod, void *m);

#endif /* NMSG_PBMOD_H */
