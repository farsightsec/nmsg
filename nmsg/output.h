/*
 * Copyright (c) 2008-2019 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NMSG_OUTPUT_H
#define NMSG_OUTPUT_H

/*! \file nmsg/output.h
 * \brief Write nmsg containers to output streams.
 *
 * Nmsg payloads can be buffered and written to a file descriptor, or
 * converted to presentation format and written to a file descriptor.
 *
 * <b>MP:</b>
 *	\li Clients must ensure synchronized access when writing to an
 *	nmsg_output_t object.
 *
 * <b>Reliability:</b>
 *	\li Clients must not touch the underlying file descriptor.
 */

/**
 * An enum identifying the underlying implementation of an nmsg_output_t object.
 * This is used for nmsg_io's close event notification.
 */
typedef enum {
	nmsg_output_type_stream,
	nmsg_output_type_pres,
	nmsg_output_type_callback,
	nmsg_output_type_json,
} nmsg_output_type;

/**
 * Initialize a new byte-stream nmsg output.
 *
 * For efficiency reasons, files should probably be opened with a bufsz of
 * #NMSG_WBUFSZ_MAX.
 *
 * \param[in] fd Writable file descriptor.
 *
 * \param[in] bufsz Value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_file(int fd, size_t bufsz);

/**
 * Initialize a new datagram socket nmsg output.
 *
 * For UDP sockets which are physically transported over an Ethernet,
 * #NMSG_WBUFSZ_ETHER or #NMSG_WBUFSZ_JUMBO (for jumbo frame Ethernets) should
 * be used for bufsz.
 *
 * \param[in] fd Writable datagram socket.
 *
 * \param[in] bufsz Value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_sock(int fd, size_t bufsz);

/**
 * Initialize a new ZMQ socket NMSG output.
 *
 * \param[in] s ZMQ output socket.
 *
 * \param[in] bufsz Value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_zmq(void *s, size_t bufsz);

/**
 * Initialize a new Kafka producer NMSG output.
 *
 * \param[in] s Kafka producer context.
 *
 * \param[in] bufsz Value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_output_t
nmsg_output_open_kafka(void *s, size_t bufsz);

/**
 * Create an ZMQ socket and initialize a new NMSG stream output from it.
 *
 * This function is a wrapper for nmsg_output_open_zmq(). Instead of taking an
 * already initialized ZMQ socket object, it takes an endpoint argument like
 * zmq_connect() and zmq_bind() do which is a string containing a
 * "transport://address" specification and initializes a ZMQ socket object.
 * However, this endpoint string will be munged in order to support additional
 * functionality:
 *
 * The caller may select between a bound or connected ZMQ socket by appending
 * ",accept" or ",connect" to the endpoint argument. (If not given, this
 * function behaves as if ",connect" was passed.) That is, ",accept" uses
 * zmq_bind() to obtain a ZMQ endpoint, and ",connect" uses zmq_connect().
 *
 * The caller may additionally select between a PUB socket or a PUSH
 * socket by appending ",pubsub" or ",pushpull". (If not given, this function
 * behaves as if ",pubsub" was passed.)
 *
 * \see nmsg_input_open_zmq_endpoint()
 *
 * \param[in] zmq_ctx ZMQ context object.
 *
 * \param[in] ep ZMQ endpoint (with nmsg-specific extensions)
 *
 * \param[in] bufsz Value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_zmq_endpoint(void *zmq_ctx, const char *ep, size_t bufsz);

/**
 * Create a Kafka producer and initialize a new NMSG stream output from it.
 *
 * This function is a wrapper for nmsg_output_open_kafka(). Instead of taking an
 * already initialized Kafka producer context, it takes an endpoint argument in
 * format topic#partition@broker
 *
 * \see nmsg_input_open_kafka_endpoint()
 *
 * \param[in] addr Kafka address string
 *
 * \param[in] bufsz Value between #NMSG_WBUFSZ_MIN and #NMSG_WBUFSZ_MAX.
 *
 * \param[in] timeout in milliseconds.
*
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */

nmsg_output_t
nmsg_output_open_kafka_endpoint(const char *addr, size_t bufsz, int timeout);

/**
 * Initialize a new presentation format (ASCII lines) nmsg output.
 *
 * \param[in] fd Writable file descriptor.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_pres(int fd);

/**
 * Initialize a new JSON format nmsg output.
 *
 * JSON outputs write payloads as JSON dictionaries with keys:
 * - time:	the payload timestamp
 * - vname:	the vendor name, or "(unknown)" if not known
 * - mname:	the message type name, or "(unknown)" if not known
 * - source:	the payload source id as a hexadecimal string, if present
 * - group:	the payload group name or number, if present
 * - operator:	the payload operator name or number, if present
 * - message:  	a dictionary containing a key-value pari for each message field
 *
 * Values of repeated fields are represented as lists.
 *
 * Message modules can provide optional formatting and parsing methods
 * for fields. If a field has no formatter or parser, the following default
 * formats are used:
 * - Numeric types: JSON number
 * - Boolean: JSON bool
 * - IP address: string representation of the IP address.
 * - Enumerated types: a string with the value name if known, integer otherwise.
 * - Byte sequences: a string with the base64 encoding of the sequence.
 * - Strings: JSON strings, with invalid UTF-8 sequences replaced with U+FFFD.
 *
 * \param[in] fd Writable file descriptor.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_json(int fd);

/**
 * Initialize a new nmsg output closure. This allows a user-provided callback to
 * function as an nmsg output, for instance to participate in an nmsg_io loop.
 * The callback is responsible for disposing of each nmsg message.
 *
 * \param[in] cb Non-NULL function pointer that will be called once for each
 *	payload.
 *
 * \param[in] user Optionally NULL pointer which will be passed to the callback.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_output_t
nmsg_output_open_callback(nmsg_cb_message cb, void *user);

/**
 * Flush an nmsg_output_t object.
 *
 * This function writes out any messages in the output buffer.
 *
 * This function is only implemented for byte-stream and datagram socket
 * nmsg outputs.
 *
 * \param[in] output nmsg_output_t object.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_output_flush(nmsg_output_t output);

/**
 * Write an nmsg message to an nmsg_output_t object.
 *
 * nmsg_output_write() does not deallocate the nmsg message object. Callers
 * should call nmsg_message_destroy() when finished with a message object.
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] msg nmsg message to be serialized and written to 'output'.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_output_write(nmsg_output_t output, nmsg_message_t msg);

/**
 * Close an nmsg_output_t object.
 *
 * \param[in] output Pointer to an nmsg_output_t object.
 *
 * \return #nmsg_res_success
 */
nmsg_res
nmsg_output_close(nmsg_output_t *output);

/**
 * Make an nmsg_output_t socket output buffered or unbuffered.
 *
 * By default, file and socket nmsg_output_t outputs are buffered. Extremely low
 * volume output streams should probably be unbuffered to reduce latency.
 *
 * \param[in] output Socket nmsg_output_t object.
 *
 * \param[in] buffered True (buffered) or false (unbuffered).
 */
void
nmsg_output_set_buffered(nmsg_output_t output, bool buffered);

/**
 * Filter an nmsg_output_t for a given vendor ID / message type.
 *
 * NMSG messages whose vid and msgtype fields do not match the filter will not
 * be output and will instead be silently discarded.
 *
 * Calling this function with vid=0 and msgtype=0 will disable the filter.
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] vid Vendor ID.
 *
 * \param[in] msgtype Message type.
 */
void
nmsg_output_set_filter_msgtype(nmsg_output_t output, unsigned vid, unsigned msgtype);

/**
 * Filter an nmsg_output_t for a given vendor ID / message type.
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] vname Vendor ID name.
 *
 * \param[in] mname Message type name.
 */
nmsg_res
nmsg_output_set_filter_msgtype_byname(nmsg_output_t output,
				      const char *vname, const char *mname);

/**
 * Limit the payload output rate.
 *
 * The caller of nmsg_output_set_rate() is responsible for reclaiming
 * unused nmsg_rate_t objects with nmsg_rate_destroy().
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] rate nmsg_rate_t object or NULL to disable rate limiting.
 */
void
nmsg_output_set_rate(nmsg_output_t output, nmsg_rate_t rate);

/**
 * Set the line continuation string for presentation format output. The default
 * is "\n".
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] endline End-of-line character string.
 */
void
nmsg_output_set_endline(nmsg_output_t output, const char *endline);

/**
 * Set the 'source' field on all output NMSG payloads. This has no effect on
 * non-NMSG outputs.
 *
 * The source ID must be positive.
 *
 * \param[in] output NMSG stream nmsg_output_t object.
 *
 * \param[in] source Source ID.
 */
void
nmsg_output_set_source(nmsg_output_t output, unsigned source);

/**
 * Set the 'operator' field on all output NMSG payloads. This has no effect on
 * non-NMSG outputs.
 *
 * The operator ID must be positive.
 *
 * \param[in] output NMSG stream nmsg_output_t object.
 *
 * \param[in] operator_ Operator ID.
 */
void
nmsg_output_set_operator(nmsg_output_t output, unsigned operator_);

/**
 * Set the 'group' field on all output NMSG payloads. This has no effect on
 * non-NMSG outputs.
 *
 * The group ID must be positive.
 *
 * \param[in] output NMSG stream nmsg_output_t object.
 *
 * \param[in] group Group ID.
 */
void
nmsg_output_set_group(nmsg_output_t output, unsigned group);

/**
 * Enable or disable zlib compression of output NMSG containers.
 *
 * \param[in] output nmsg_output_t object.
 *
 * \param[in] zlibout True (zlib enabled) or false (zlib disabled).
 */
void
nmsg_output_set_zlibout(nmsg_output_t output, bool zlibout);

#endif /* NMSG_OUTPUT_H */
