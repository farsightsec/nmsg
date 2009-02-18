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

/*****
 ***** Module Info
 *****/

/*! \file nmsg/pbmod.h
 * \brief Protocol buffer modules.
 *
 * Protocol buffer modules extend nmsg by allowing new message types to be
 * implemented in dynamically loaded plugins. Pbmods identify the types of
 * messages they can handle by registering a vendor ID number and one or
 * more per-vendor message type numbers with the pbmod loader. Functions
 * for creating and interpreting nmsg payloads must be provided.
 *
 * Pbmods are dynamically loaded shared objects that must provide a symbol
 * called 'nmsg_pbmod_ctx' which will be interpreted as an object of type
 * struct nmsg_pbmod. The first field of this structure is the version of
 * the API between libnmsg and the extension module; module developers
 * should use this header file for the struct nmsg_pbmod definition and
 * assign this field the value NMSG_PBMOD_VERSION.
 *
 * Modules must register a single vendor ID and an array of message types
 * to be handled. This array must be terminated by the sentinel
 * NMSG_IDNAME_END.
 *
 * Modules must be reentrant. An opaque pointer may be returned by the
 * module initialization function; this pointer will be provided to
 * module functions that require state and will be provided to the module
 * finalization function for deallocation.
 *
 * For managing, loading, and unloading pbmods as a group, see the pbmodset
 * interface.
 *
 * \li MP:
 *	nmsg_pbmod_init() returns an opaque pointer which must be used to
 *	differentiate threads.
 */

/***
 *** Imports
 ***/

/* Imports */
 
#include <sys/types.h>
#include <stdint.h>

#include <nmsg.h>
#include <nmsg/res.h>

/***
 *** Types
 ***/

typedef struct nmsg_pbmod *nmsg_pbmod;

typedef nmsg_res (*nmsg_pbmod_init_fp)(void **clos, int debug);
typedef nmsg_res (*nmsg_pbmod_fini_fp)(void **clos);
typedef nmsg_res (*nmsg_pbmod_pbuf_to_pres_fp)(Nmsg__NmsgPayload *np,
					       char **pres,
					       const char *endline);
typedef nmsg_res (*nmsg_pbmod_pres_to_pbuf_fp)(void *clos, const char *pres);
typedef nmsg_res (*nmsg_pbmod_pres_to_pbuf_finalize_fp)(void *clos,
							uint8_t **pbuf,
							size_t *sz);

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

struct nmsg_pbmod {
	int					pbmver;
	nmsg_pbmod_init_fp			init;
	nmsg_pbmod_fini_fp			fini;
	nmsg_pbmod_pbuf_to_pres_fp		pbuf_to_pres;
	nmsg_pbmod_pres_to_pbuf_fp		pres_to_pbuf;
	nmsg_pbmod_pres_to_pbuf_finalize_fp	pres_to_pbuf_finalize;
	const ProtobufCMessageDescriptor	*pbdescr;
	const ProtobufCFieldDescriptor		*pbfields;
	struct nmsg_pbmod_field			*fields;
	struct nmsg_idname			vendor;
	struct nmsg_idname			msgtype[];
};

/***
 *** Functions
 ***/

nmsg_res
nmsg_pbmod_init(nmsg_pbmod mod, void **clos, int debug);
/*%<
 * Initialize a protocol buffer module.
 *
 * Requires:
 *
 * \li	'mod' is an initialized pbmod.
 *
 * \li	'*clos' is where an opaque pointer specific to this instantiation
 *	of the module will be stored. This pointer must be supplied to
 *	nmsg_pbmod functions taking a 'clos' parameter.
 *
 * \li	'debug' is the debug level. No debug messages should be generated
 *	at debug level 0.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 * \li	nmsg_res_memfail
 * \li	nmsg_res_notimpl
 */

nmsg_res
nmsg_pbmod_fini(nmsg_pbmod mod, void **clos);
/*%<
 * Finalize a protocol buffer module.
 *
 * Requires:
 *
 * \li	'clos' is the opaque pointer returned by the module initialization
 *	function.
 *
 * Ensures:
 * 
 * \li	All resources allocated by the module are released.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 * \li	nmsg_res_notimpl
 */

nmsg_res
nmsg_pbmod_pbuf_to_pres(nmsg_pbmod mod, Nmsg__NmsgPayload *np, char **pres,
			const char *endline);
/*%<
 * Convert a protocol buffer nmsg payload to presentation form.
 *
 * Requires:
 *
 * \li	'mod' is an initialized pbmod.
 *
 * \li	'np' is an nmsg payload which can be interpreted by 'mod'.
 *
 * \li	'pres' is the location in which to store the presentation form of
 *	'np'.
 *
 * \li	'endline' is the string which should be used for line continuation.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 * \li	nmsg_res_memfail
 * \li	nmsg_res_notimpl
 */

nmsg_res
nmsg_pbmod_pres_to_pbuf(nmsg_pbmod mod, void *clos, const char *pres);
/*%<
 * Convert a presentation format line to a protocol buffer nmsg payload.
 * Since the presentation format stream is line-delimited, not every line
 * will necessarily result in a serialized pbuf.
 *
 * When nmsg_res_pbuf_ready is returned, the nmsg_pbmod_pres_to_pbuf_finalize()
 * function should be used to obtain the serialized pbuf.
 *
 * Requires:
 *
 * \li	'mod' is an initialized pbmod.
 *
 * \li	'clos' is the opaque pointer returned by the module initialization
 *	function.
 *
 * \li	'pres' is a line of presentation form input of the type handled by
 *	'mod'.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 * \li	nmsg_res_memfail
 * \li	nmsg_res_notimpl
 * \li	nmsg_res_parse_error
 * \li	nmsg_res_pbuf_ready
 */

nmsg_res
nmsg_pbmod_pres_to_pbuf_finalize(nmsg_pbmod mod, void *clos, uint8_t **pbuf,
				 size_t *sz);
/*%<
 * After a call to nmsg_pbmod_pres_to_pbuf() return nmsg_res_pbuf_ready, this
 * function will return the serialized pbuf. The caller is responsible for
 * freeing the pointer returned in *pbuf.
 *
 * Requires:
 *
 * \li	'mod' is an initialized pbmod.
 *
 * \li	'clos' is the opaque pointer returned by the module initialization
 *	function.
 *
 * \li	'pbuf' is where the serialized payload will be stored.
 *
 * \li	'sz' is where the length of the serialized payload will be stored.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_failure
 * \li	nmsg_res_memfail
 * \li	nmsg_res_notimpl
 */

nmsg_res
nmsg_pbmod_message_init(struct nmsg_pbmod *mod, void *m);
/*%<
 * Initialize a message. This function is only implemented for automatic
 * modules.
 *
 * Requires:
 *
 * \li	'mod' is an initialized automatic pbmod.
 *
 * \li	'm' is a pointer to a pbnmsg module-specific message structure.
 *
 * Returns:
 *
 * \li	nmsg_res_success
 * \li	nmsg_res_notimpl
 */

nmsg_res
nmsg_pbmod_message_reset(struct nmsg_pbmod *mod, void *m);
/*%<
 * Reset a message. This function is only implemented for automatic
 * modules.
 *
 * This function should be used after the message has been serialized.
 * All message field quantifiers will be reset and fields allocated with
 * malloc will be freed.
 *
 * Requires:
 *
 * \li	'mod' is an initialized automatic pbmod.
 *
 * \li 'm' is a pointer to a pbnmsg module-specific message structure.
 */

/***
 *** Constants
 ***/

/*%
 * Version number of the nmsg pbmod API.
 */
#define NMSG_PBMOD_VERSION	3

#endif /* NMSG_PBMOD_H */
