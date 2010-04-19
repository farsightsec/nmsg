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

#ifndef NMSG_MSGMOD_PLUGIN_H
#define NMSG_MSGMOD_PLUGIN_H

#include <sys/types.h>
#include <stdint.h>

#include <nmsg.h>

#include <google/protobuf-c/protobuf-c.h>
#include <nmsg/nmsg.pb-c.h>

struct nmsg_msgmod_field;

/** Version number of the nmsg msgmod API. */
#define NMSG_MSGMOD_VERSION	7

/** \see nmsg_msgmod_init() */
typedef nmsg_res (*nmsg_msgmod_init_fp)(void **clos);

/** \see nmsg_msgmod_fini() */
typedef nmsg_res (*nmsg_msgmod_fini_fp)(void **clos);

/** \see nmsg_msgmod_payload_to_pres() */
typedef nmsg_res (*nmsg_msgmod_payload_to_pres_fp)(Nmsg__NmsgPayload *np,
						   char **pres,
						   const char *endline);

/** \see nmsg_msgmod_ipdg_to_payload() */
typedef nmsg_res (*nmsg_msgmod_ipdg_to_payload_fp)(void *clos,
						   const struct nmsg_ipdg *dg,
						   uint8_t **pbuf, size_t *sz);

typedef nmsg_res (*nmsg_msgmod_pkt_to_payload_fp)(void *clos,
						  nmsg_pcap_t pcap,
						  nmsg_message_t *m);

/** Per-message load function. */
typedef nmsg_res (*nmsg_msgmod_msg_load_fp)(nmsg_message_t m, void **msg_clos);

/** Per-message finalization function. */
typedef nmsg_res (*nmsg_msgmod_msg_fini_fp)(nmsg_message_t m, void *msg_clos);

/** Custom field printer function. */
typedef nmsg_res (*nmsg_msgmod_field_print_fp)(nmsg_message_t m,
					       struct nmsg_msgmod_field *field,
					       void *ptr,
					       struct nmsg_strbuf *sb,
					       const char *endline);

/** Custom field accessor function. */
typedef nmsg_res (*nmsg_msgmod_field_get_fp)(nmsg_message_t m,
					     struct nmsg_msgmod_field *field,
					     unsigned val_idx,
					     void **data,
					     size_t *len,
					     void *msg_clos);

/** Convenience macro. */
#define NMSG_MSGMOD_FIELD_PRINTER(funcname) \
	nmsg_res funcname(nmsg_message_t m, \
			  struct nmsg_msgmod_field *field, \
			  void *ptr, \
			  struct nmsg_strbuf *sb, \
			  const char *endline)

/** Convenience macro. */
#define NMSG_MSGMOD_FIELD_GETTER(funcname) \
	nmsg_res funcname(nmsg_message_t m, \
			  struct nmsg_msgmod_field *field, \
			  unsigned val_idx, \
			  void **data, \
			  size_t *len, \
			  void *msg_clos)

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

	/** Name of the field. */
	const char				*name;

	/** Flags for this field. */
	unsigned				flags;

	/** Optional custom field printer function. */
	nmsg_msgmod_field_print_fp		print;

	/** Optional custom field getter function. */
	nmsg_msgmod_field_get_fp		get;

	/** \private, must be initialized to NULL. */
	const ProtobufCFieldDescriptor		*descr;

	/** \private Reserved fields. */
	void					*_reserved3;
	void					*_reserved2;
	void					*_reserved1;
	void					*_reserved0;
};

/** Element ending a struct nmsg_msgmod_field array. */
#define NMSG_MSGMOD_FIELD_END	{ 0, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL }

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
 * "Opaque" modules must provide functions to encode and decode the message
 * payload.
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
struct nmsg_msgmod_plugin {
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
	 * Module initialization function. May be NULL.
	 */
	nmsg_msgmod_init_fp			init;

	/**
	 * Module finalization function. May be NULL.
	 */
	nmsg_msgmod_fini_fp			fini;

	/**
	 * Per-message load function.
	 * This function is called when loading serialized messages, but not
	 * when initializing messages from scratch.
	 */
	nmsg_msgmod_msg_load_fp			msg_load;

	/**
	 * Per-message finalization function.
	 */
	nmsg_msgmod_msg_fini_fp			msg_fini;

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
	 * Module function to convert reassembled IP datagrams to NMSG
	 * payloads.
	 * Must be <b>unset</b> for transparent modules.
	 * May be <b>set</b> for opaque modules.
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

	/**
	 * Module function to convert raw IP packets to NMSG payloads.
	 * Must be <b>unset</b> for transparent modules.
	 * May be <b>set</b> for opaque modules.
	 * If set, the ipdg_to_payload field will be ignored.
	 */
	nmsg_msgmod_pkt_to_payload_fp		pkt_to_payload;

	/**
	 * \private Reserved fields.
	 */
	void					*_reserved10;
	void					*_reserved9;
	void					*_reserved8;
	void					*_reserved7;
	void					*_reserved6;
	void					*_reserved5;
	void					*_reserved4;
	void					*_reserved3;
	void					*_reserved2;
	void					*_reserved1;
	void					*_reserved0;
};

#endif /* NMSG_MSGMOD_PLUGIN_H */
