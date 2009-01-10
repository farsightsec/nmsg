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

#ifndef NMSG_CONSTANTS_H
#define NMSG_CONSTANTS_H

/***
 *** Constants
 ***/

/*%
 * Four-octet magic sequence seen at the beginning of a serialized nmsg.
 */
#define NMSG_MAGIC		{'N', 'M', 'S', 'G'}

/*%
 * Current version number of the nmsg serialization format.
 */
#define NMSG_VERSION		2U

/*%
 * Number of octets in an nmsg header (magic + version).
 */
#define NMSG_HDRSZ		6

/*%
 * Number of octets in an nmsg header (magic + version + length).
 */
#define NMSG_HDRLSZ_V2		10

/*%
 * Number of octets in the nmsg v1 header length field.
 */
#define NMSG_LENHDRSZ_V1	2

/*%
 * Number of octets in the nmsg v2 header length field.
 */
#define NMSG_LENHDRSZ_V2	4

/*%<
 * Maximum number of octets in an nmsg payload header.
 */
#define NMSG_PAYHDRSZ		64

/*%
 * Minimum number of octets that an nmsg wbuf must hold.
 */
#define NMSG_WBUFSZ_MIN		512

/*%
 * Maximum number of octets that an nmsg wbuf can hold.
 */
#define NMSG_WBUFSZ_MAX		1048576

/*%
 * Number of octets that an nmsg wbuf destined for transport over a jumbo
 * frame Ethernet should hold.
 */
#define NMSG_WBUFSZ_JUMBO	8192

/*%
 * Number of octets that an nmsg wbuf destined for transport over an
 * Ethernet should hold.
 */
#define NMSG_WBUFSZ_ETHER	1280

/*%
 * Number of octets than an nmsg rbuf must hold. Since an nmsg stream is
 * delimited by length fields, the worst case amount of storage needed is
 * twice the maximum length of an nmsg container.
 */
#define NMSG_RBUFSZ		(2 * NMSG_WBUFSZ_MAX)

#endif
