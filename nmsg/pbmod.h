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
 * Pbmods are dynamically loaded shared objects that must provide a symbol
 * called 'nmsg_pbmod_ctx' which will be interpreted as an array of pointers to
 * objects of type struct nmsg_pbmod. The first field of this structure is the
 * version of the API between libnmsg and the extension module; module
 * developers should use this header file for the struct nmsg_pbmod definition
 * and assign this field the value NMSG_PBMOD_VERSION. This array must be
 * terminated by a NULL pointer.
 *
 * Modules must be reentrant. An opaque pointer may be returned by the module
 * initialization function; this pointer will be provided to module functions
 * that require state and will be provided to the module finalization function
 * for deallocation.
 *
 * If a protocol buffer message schema is restricted in a certain way, a C stub
 * consisting of data definitions only can be used to interface with libnmsg.
 * This is called an "automatic module".
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

/**
 * Version number of the nmsg pbmod API.
 */
#define NMSG_PBMOD_VERSION	4

typedef nmsg_res (*nmsg_pbmod_init_fp)(void **clos);
typedef nmsg_res (*nmsg_pbmod_fini_fp)(void **clos);
typedef nmsg_res (*nmsg_pbmod_pbuf_to_pres_fp)(Nmsg__NmsgPayload *np,
					       char **pres,
					       const char *endline);
typedef nmsg_res (*nmsg_pbmod_pres_to_pbuf_fp)(void *clos, const char *pres);
typedef nmsg_res (*nmsg_pbmod_pres_to_pbuf_finalize_fp)(void *clos,
							uint8_t **pbuf,
							size_t *sz);
typedef nmsg_res (*nmsg_pbmod_ipdg_to_pbuf_fp)(void *clos,
					       const struct nmsg_ipdg *dg,
					       uint8_t **pbuf, size_t *sz);

typedef enum {
	nmsg_pbmod_ft_enum,
	nmsg_pbmod_ft_string,
	nmsg_pbmod_ft_mlstring,
	nmsg_pbmod_ft_ip,
	nmsg_pbmod_ft_uint16,
	nmsg_pbmod_ft_uint32,
	nmsg_pbmod_ft_uint64,
	nmsg_pbmod_ft_int16,
	nmsg_pbmod_ft_int32,
	nmsg_pbmod_ft_int64,
} nmsg_pbmod_field_type;

struct nmsg_pbmod_field {
	nmsg_pbmod_field_type			type;
	const char				*name;
	const ProtobufCFieldDescriptor		*descr;
};
#define NMSG_PBMOD_FIELD_END	{ 0, NULL, NULL }

struct nmsg_pbmod {
	int					pbmver;
	nmsg_pbmod_init_fp			init;
	nmsg_pbmod_fini_fp			fini;
	nmsg_pbmod_pbuf_to_pres_fp		pbuf_to_pres;
	nmsg_pbmod_pres_to_pbuf_fp		pres_to_pbuf;
	nmsg_pbmod_pres_to_pbuf_finalize_fp	pres_to_pbuf_finalize;
	nmsg_pbmod_ipdg_to_pbuf_fp		ipdg_to_pbuf;
	const ProtobufCMessageDescriptor	*pbdescr;
	const ProtobufCFieldDescriptor		*pbfields;
	struct nmsg_pbmod_field			*fields;
	struct nmsg_idname			vendor;
	struct nmsg_idname			msgtype;
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
