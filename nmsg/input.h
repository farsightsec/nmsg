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

#include <stdbool.h>

#include <nmsg.h>

/** 
 * An enum identifying the underlying implementation of an nmsg_input_t object.
 * This is used for nmsg_io's close event notification.
 */
typedef enum {
	nmsg_input_type_stream,	/*%< nmsg payloads from file or socket */
	nmsg_input_type_pcap,	/*%< pcap packets from file or interface */
	nmsg_input_type_pres	/*%< presentation form */
} nmsg_input_type;

/**
 * Initialize a new nmsg stream input from a byte-stream file source.
 *
 * \param[in] fd readable file descriptor from a byte-stream source.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_file(int fd);

/**
 * Initialize a new nmsg stream input from a datagram socket source.
 *
 * \param[in] fd readable datagram socket.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_sock(int fd);

/**
 * Initialize a new nmsg presentation form input from a file descriptor.
 *
 * \param[in] fd readable file descriptor.
 *
 * \param[in] msgmod handle that implements the desired presentation form
 *	to nmsg conversion.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_pres(int fd, nmsg_msgmod_t msgmod);

/**
 * Initialize a new nmsg pcap input from a pcap descriptor.
 *
 * \param[in] pcap descriptor returned by libpcap. Supported data link types are
 * those supported by nmsg_ipdg_parse_pcap().
 *
 * \param[in] msgmod handle that implements the desired IP datagram to
 *	nmsg conversion.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_input_t
nmsg_input_open_pcap(nmsg_pcap_t pcap, nmsg_msgmod_t msgmod);

/**
 * Close an nmsg_input_t object and release all associated resources.
 *
 * \param[in] input valid pointer to an nmsg_input_t object.
 *
 * \return #nmsg_res_success
 */
nmsg_res
nmsg_input_close(nmsg_input_t *input);

/**
 * Loop over an input stream and call a user-provided function for each payload.
 *
 * \param[in] input valid nmsg_input_t.
 *
 * \param[in] count non-negative to indicate a finite number of payloads to
 *	process or negative to indicate all available payloads should be
 *	processed.
 *
 * \param[in] cb non-NULL function pointer that will be called once for each
 *	payload.
 *
 * \param[in] user optionally NULL pointer which will be passed to the callback.
 *
 * \return any of nmsg_input_read()'s return values.
 */
nmsg_res
nmsg_input_loop(nmsg_input_t input, int count, nmsg_cb_message cb, void *user);

/**
 * Read one nmsg message from an input stream.
 *
 * \param[in] input valid nmsg_input_t.
 *
 * \param[out] msg pointer to where an nmsg_message_t object may be stored.
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
 * Filter an nmsg_input_t for a given vendor ID / message type.
 *
 * NMSG messages whose vid and and msgtype fields do not match the filter will
 * be silently discarded when reading from the input.
 *
 * Calling this function with vid=0 and msgtype=0 will disable the filter.
 *
 * \param[in] input nmsg_input_t object.
 *
 * \param[in] vid vendor ID.
 *
 * \param[in] msgtype message type.
 */
void
nmsg_input_set_filter_msgtype(nmsg_input_t input,
			      unsigned vid, unsigned msgtype);

/**
 * Filter an nmsg_input_t for a given vendor ID / message type.
 *
 * \param[in] input nmsg_input_t object.
 *
 * \param[in] vname vendor ID name.
 *
 * \param[in] mname message type name.
 */
nmsg_res
nmsg_input_set_filter_msgtype_byname(nmsg_input_t input,
				     const char *vname, const char *mname);

/**
 * Set a source filter for input NMSG payloads. This has no effect on non-NMSG
 * inputs. Only NMSG payloads whose source field matches the source filter
 * will be output by nmsg_input_read() or nmsg_input_loop().
 *
 * \param[in] input NMSG stream nmsg_input_t object.
 *
 * \param[in] source source ID filter, 0 to disable.
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
 * \param[in] source operator ID filter, 0 to disable.
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
 * \param[in] source group ID filter, 0 to disable.
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

#endif /* NMSG_INPUT_H */
