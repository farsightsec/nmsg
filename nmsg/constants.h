/*
 * Copyright (c) 2008 by Farsight Security, Inc.
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

#ifndef NMSG_CONSTANTS_H
#define NMSG_CONSTANTS_H

/*! \file nmsg/constants.h
 * \brief Nmsg constants.
 */

/**
 * Four-octet magic sequence seen at the beginning of a serialized NMSG.
 */
#define NMSG_MAGIC		{'N', 'M', 'S', 'G'}

/**
 * Current version number of the NMSG serialization format. With the
 * introduction of #NMSG_LIBRARY_VERSION, #NMSG_PROTOCOL_VERSION was
 * introduced to disambiguate version constants. It is assumed
 * #NMSG_VERSION will be deprecated and removed in a future release.
 */
#define NMSG_VERSION		2U
#define NMSG_PROTOCOL_VERSION	NMSG_VERSION

/**
 * Number of octets in an NMSG header (magic + version).
 */
#define NMSG_HDRSZ		6

/**
 * Number of octets in an NMSG header (magic + version + length).
 */
#define NMSG_HDRLSZ_V2		10

/**
 * Number of octets in the NMSG v1 header length field.
 */
#define NMSG_LENHDRSZ_V1	2

/**
 * Number of octets in the NMSG v2 header length field.
 */
#define NMSG_LENHDRSZ_V2	4

/**
 * Maximum number of octets in an NMSG payload header.
 */
#define NMSG_PAYHDRSZ		64

/**
 * Minimum number of octets that an nmsg wbuf must hold.
 */
#define NMSG_WBUFSZ_MIN		512

/**
 * Maximum number of octets that an nmsg wbuf can hold.
 */
#define NMSG_WBUFSZ_MAX		1048576

/**
 * Number of octets that an nmsg wbuf destined for transport over a jumbo
 * frame Ethernet should hold.
 */
#define NMSG_WBUFSZ_JUMBO	8192

/**
 * Number of octets that an nmsg wbuf destined for transport over an
 * Ethernet should hold.
 */
#define NMSG_WBUFSZ_ETHER	1280

/**
 * Number of octets than an nmsg rbuf must hold. Since an nmsg stream is
 * delimited by length fields, the worst case amount of storage needed is
 * twice the maximum length of an nmsg container.
 */
#define NMSG_RBUFSZ		(2 * NMSG_WBUFSZ_MAX)

/**
 * Number of milliseconds to wait for data on an nmsg socket before
 * returning nmsg_res_again.
 */
#define NMSG_RBUF_TIMEOUT	500

/**
 * Default libpcap snap length when reading from a live interface.
 */
#define NMSG_DEFAULT_SNAPLEN	1522

/**
 * Maximize size of an IP datagram.
 */
#define NMSG_IPSZ_MAX		65536

/* NMSG flags */

/**
 * NMSG container is zlib compressed.
 */
#define NMSG_FLAG_ZLIB		0x01

/**
 * NMSG container is fragmented.
 */
#define NMSG_FLAG_FRAGMENT	0x02

#endif
