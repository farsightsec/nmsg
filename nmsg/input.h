/*
 * Copyright (c) 2008-2015 by Farsight Security, Inc.
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

#ifndef NMSG_INPUT_H
#define NMSG_INPUT_H

/*! \file nmsg/input.h
 * \brief Convert input streams to nmsg format.
 *
 * Nmsg can import data into a stream of payloads from several different input
 * sources:
 *
 *	\li Wire-format NMSG containers which contain one or more binary
 *	payloads that can be read from file or datagram socket sources. This is
 *	the native NMSG interchange format.
 *
 *	\li libpcap packets from a pcap savefile or network interface that will
 *	be reassembled into IP datagrams and passed to a message format specific
 *	function for conversion into nmsg payloads.
 *
 *	\li Presentation format data (ASCII lines) read from a file, converted
 *	by a message format specific function into nmsg payloads.
 *
 * <b>MP:</b>
 *	\li Clients must ensure synchronized access when reading from an
 *	nmsg_input_t object.
 *
 * <b>Reliability:</b>
 *	\li Clients must not touch the underlying file descriptor or pcap_t
 *	object. Cleanup will be handled by the nmsg_input_close() function.
 *
 * <b>Resources:</b>
 *	\li An internal buffer will be allocated and used until an nmsg_input_t
 *	object is destroyed.
 */

/** 
 * An enum identifying the underlying implementation of an nmsg_input_t object.
 * This is used for nmsg_io's close event notification.
 */
typedef enum {
	nmsg_input_type_stream,	/*%< NMSG payloads from file or socket */
	nmsg_input_type_pcap,	/*%< pcap packets from file or interface */
	nmsg_input_type_pres,	/*%< presentation form */
	nmsg_input_type_callback,
	nmsg_input_type_json,	/*%< JSON form */
} nmsg_input_type;

/**
 * Initialize a new NMSG stream input from a byte-stream file source.
 *
 * \param[in] fd Readable file descriptor from a byte-stream source.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_file(int fd);

/**
 * Initialize a new NMSG stream input from a datagram socket source.
 *
 * \param[in] fd Readable datagram socket.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_sock(int fd);

/**
 * Initialize a new NMSG stream input from an XS socket source.
 *
 * \param[in] s XS socket.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_xs(void *s);

/**
 * Create an XS socket and initialize a new NMSG stream input from it.
 *
 * This function is a wrapper for nmsg_input_open_xs(). Instead of taking an
 * already initialized XS socket object, it takes an endpoint argument like
 * xs_connect() and xs_bind() do which is a string containing a
 * "transport://address" specification and initializes an XS socket object.
 * However, this endpoint string will be munged in order to support additional
 * functionality:
 *
 * The caller may select between a bound or connected XS socket by appending
 * ",accept" or ",connect" to the endpoint argument. (If not given, this
 * function behaves as if ",connect" was passed.) That is, ",accept" uses
 * xs_bind() to obtain a XS endpoint, and ",connect" uses xs_connect().
 *
 * The caller may additionally select between a SUB socket or a PULL
 * socket by appending ",pubsub" or ",pushpull". (If not given, this function
 * behaves as if ",pubsub" was passed.)
 *
 * \see nmsg_output_open_xs_endpoint()
 *
 * \param[in] xs_ctx XS context object.
 *
 * \param[in] ep XS endpoint (with nmsg-specific extensions)
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_xs_endpoint(void *xs_ctx, const char *ep);

/**
 * Initialize a new nmsg input closure. This allows a user-provided callback to
 * function as an nmsg input, for instance to participate in an nmsg_io loop.
 * The callback is responsible for creating an nmsg_message_t object and
 * returning it to the caller.
 *
 * \param[in] cb Non-NULL function pointer.
 *
 * \param[in] user Optionally NULL pointer which will be passed to the callback.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_callback(nmsg_cb_message_read cb, void *user);

/**
 * Initialize a new "null source" NMSG stream input.
 *
 * A "null source" means the actual gathering of input is not performed by
 * the library but rather by the caller. A "null source" nmsg_input_t thus
 * serves only to hold the state associated with the stream.
 *
 * Calling nmsg_input_loop() or nmsg_input_read() on a "null source" input
 * will fail. Callers instead need to use nmsg_input_read_null().
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_null(void);

/**
 * Initialize a new NMSG presentation form input from a file descriptor.
 *
 * \param[in] fd Readable file descriptor.
 *
 * \param[in] msgmod Handle that implements the desired presentation form
 *	to NMSG conversion.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_pres(int fd, nmsg_msgmod_t msgmod);

/**
 * Initialize a new NMSG JSON form input from a file descriptor.
 *
 * See nmsg_output_open_json for details of the JSON format.
 *
 * \param[in] fd Readable file descriptor.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_json(int fd);

/**
 * Initialize a new NMSG pcap input from a pcap descriptor.
 *
 * \param[in] pcap Descriptor returned by libpcap. Supported data link types are
 * those supported by nmsg_ipdg_parse_pcap().
 *
 * \param[in] msgmod Handle that implements the desired IP datagram to
 *	NMSG conversion.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_pcap(nmsg_pcap_t pcap, nmsg_msgmod_t msgmod);

/**
 * Close an nmsg_input_t object and release all associated resources.
 *
 * \param[in] input Valid pointer to an nmsg_input_t object.
 *
 * \return #nmsg_res_success
 */
nmsg_res
nmsg_input_close(nmsg_input_t *input);

/**
 * Loop over an input stream and call a user-provided function for each payload.
 *
 * \param[in] input Valid nmsg_input_t.
 *
 * \param[in] count Non-negative to indicate a finite number of payloads to
 *	process or negative to indicate all available payloads should be
 *	processed.
 *
 * \param[in] cb Non-NULL function pointer that will be called once for each
 *	payload.
 *
 * \param[in] user Optionally NULL pointer which will be passed to the callback.
 *
 * \return Any of nmsg_input_read()'s return values.
 */
nmsg_res
nmsg_input_loop(nmsg_input_t input, int count, nmsg_cb_message cb, void *user);

/**
 * Break out of an #nmsg_input_loop() early.
 *
 * \param[in] input Valid nmsg_input_t.
 */
void
nmsg_input_breakloop(nmsg_input_t input);

/**
 * Read one NMSG message from an input stream.
 *
 * \param[in] input Valid nmsg_input_t.
 *
 * \param[out] msg Pointer to where an nmsg_message_t object may be stored.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_again
 * \return #nmsg_res_eof
 * \return #nmsg_res_magic_mismatch
 * \return #nmsg_res_version_mismatch
 */
nmsg_res
nmsg_input_read(nmsg_input_t input, nmsg_message_t *msg);

/**
 * Read zero, one, or more NMSG messages from a "null source" input. The caller
 * must supply a buffer containing the serialized NMSG container. This function
 * may return #nmsg_res_success with n_msg set to zero, which indicates that the
 * NMSG container contained a fragment.
 *
 * \param[in] input Valid "null source" nmsg_input_t.
 *
 * \param[in] buf Input buffer containing a serialized NMSG container.
 *
 * \param[in] buf_len Length of input buffer.
 *
 * \param[in] ts Current "time". May be NULL to indicate the current wall clock
 * time.
 *
 * \param[out] msg Pointer to where an array of nmsg_message_t objects may be
 * stored.
 *
 * \param[out] n_msg Pointer to where the size of the output array will be
 * stored.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_again
 * \return #nmsg_res_magic_mismatch
 * \return #nmsg_res_version_mismatch
 */
nmsg_res
nmsg_input_read_null(nmsg_input_t input, uint8_t *buf, size_t buf_len,
		     struct timespec *ts, nmsg_message_t **msg, size_t *n_msg);

/**
 * Filter an nmsg_input_t for a given vendor ID / message type.
 *
 * NMSG messages whose vid and and msgtype fields do not match the filter will
 * be silently discarded when reading from the input.
 *
 * Calling this function with vid=0 and msgtype=0 will disable the filter.
 *
 * \param[in] input nmsg_input_t object.
 *
 * \param[in] vid Vendor ID.
 *
 * \param[in] msgtype Message type.
 */
void
nmsg_input_set_filter_msgtype(nmsg_input_t input,
			      unsigned vid, unsigned msgtype);

/**
 * Filter an nmsg_input_t for a given vendor ID / message type.
 *
 * \param[in] input nmsg_input_t object.
 *
 * \param[in] vname Vendor ID name.
 *
 * \param[in] mname Message type name.
 */
nmsg_res
nmsg_input_set_filter_msgtype_byname(nmsg_input_t input,
				     const char *vname, const char *mname);

/**
 * Set a source filter for input NMSG payloads. This is only effective for file,
 * socket, and xs inputs. Only NMSG payloads whose source field matches the
 * source filter will be output by nmsg_input_read() or nmsg_input_loop().
 *
 * \param[in] input NMSG stream nmsg_input_t object.
 *
 * \param[in] source Source ID filter, 0 to disable.
 */
void
nmsg_input_set_filter_source(nmsg_input_t input, unsigned source);

/**
 * Set an operator filter for input NMSG payloads. This has no effect on
 * non-NMSG inputs. Only NMSG payloads whose operator field matches the
 * operator filter will be output by nmsg_input_read() or nmsg_input_loop().
 *
 * \param[in] input NMSG stream nmsg_input_t object.
 *
 * \param[in] operator_ Operator ID filter, 0 to disable.
 */
void
nmsg_input_set_filter_operator(nmsg_input_t input, unsigned operator_);

/**
 * Set a group filter for input NMSG payloads. This has no effect on non-NMSG
 * inputs. Only NMSG payloads whose group field matches the group filter will
 * be output by nmsg_input_read() or nmsg_input_loop().
 *
 * \param[in] input NMSG stream nmsg_input_t object.
 *
 * \param[in] group Group ID filter, 0 to disable.
 */
void
nmsg_input_set_filter_group(nmsg_input_t input, unsigned group);

/**
 * Configure non-blocking I/O for a stream input.
 *
 * \param[in] input NMSG stream nmsg_input_t object.
 *
 * \param[in] flag boolean value, true to clear O_NONBLOCK on the
 *	underlying file descriptor, false to set O_NONBLOCK.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_input_set_blocking_io(nmsg_input_t input, bool flag);

/**
 * Set the target ingress byte rate for a stream input. If the target byte
 * rate is positive, reading from the input may sleep in order to maintain the
 * target consumption rate.
 *
 * Setting this value to a non-positive value will disable ingress byte rate
 * control.
 *
 * \param[in] input NMSG stream nmsg_input_t object.
 *
 * \param[in] rate Target byte rate in bytes/second.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_input_set_byte_rate(nmsg_input_t input, size_t rate);

/**
 * Enable or disable seqsrc verification on an NMSG stream nmsg_input_t object.
 * Note that for stream nmsg_input_t objects, seqsrc verification is enabled
 * by default.
 *
 * \param[in] input NMSG stream nmsg_input_t object.
 *
 * \param[in] verify boolean value, true to enable verification, false to
 *	disable verification.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_input_set_verify_seqsrc(nmsg_input_t input, bool verify);

/**
 * For UDP datagram socket nmsg_input_t objects, retrieve the total number of
 * NMSG containers that have been received since the nmsg_input_t object was
 * created.
 *
 * \param[in] input UDP socket based NMSG input object.
 *
 * \param[out] count Total number of NMSG containers received by the
 *	nmsg_input_t object during its lifetime.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_input_get_count_container_received(nmsg_input_t input, uint64_t *count);

/**
 * For UDP datagram socket nmsg_input_t objects, retrieve the total number of
 * NMSG containers that been dropped since the nmsg_input_t object was
 * created. Sequence number tracking must have been previously enabled by a
 * call to #nmsg_input_set_verify_seqsrc().
 *
 * \param[in] input UDP socket based NMSG input object.
 *
 * \param[out] count Number of NMSG containers determined to have been dropped
 *	by the nmsg_input_t object since sequence number tracking was enabled.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
*/
nmsg_res
nmsg_input_get_count_container_dropped(nmsg_input_t input, uint64_t *count);

#endif /* NMSG_INPUT_H */
