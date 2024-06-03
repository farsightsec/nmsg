#ifndef NMSG_H
#define NMSG_H

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

/*! \file nmsg.h
 * \brief Base nmsg support header.
 *
 * This header ensures that needed constants, functions, result codes,
 * vendor definitions, and opaque pointer types are defined.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <pcap.h>

#include <nmsg/res.h>
typedef enum nmsg_res nmsg_res;

typedef struct nmsg_container *	nmsg_container_t;
typedef struct nmsg_fltmod *	nmsg_fltmod_t;
typedef struct nmsg_input *	nmsg_input_t;
typedef struct nmsg_io *	nmsg_io_t;
typedef struct nmsg_message *	nmsg_message_t;
typedef struct nmsg_msgmod *	nmsg_msgmod_t;
typedef struct nmsg_output *	nmsg_output_t;
typedef struct nmsg_pcap *	nmsg_pcap_t;
typedef struct nmsg_pres *	nmsg_pres_t;
typedef struct nmsg_rate *	nmsg_rate_t;
typedef struct nmsg_random *	nmsg_random_t;
typedef struct nmsg_strbuf *	nmsg_strbuf_t;
typedef struct nmsg_zbuf *	nmsg_zbuf_t;

/**
 * Generic ID to name map.
 */
struct nmsg_idname {
	unsigned	id;	/*%< ID number */
	const char	*name;	/*%< Human readable name */
};

/**
 * Callback function for processing nmsg messages.
 *
 * \param[in] msg Valid nmsg message.
 *
 * \param[in] user User-provided pointer.
 *
 * \see nmsg_input_loop()
 * \see nmsg_output_open_callback()
 */
typedef void (*nmsg_cb_message)(nmsg_message_t msg, void *user);

/**
 * Callback function for generating nmsg messages.
 *
 * \param[out] msg Pointer to where an nmsg_message_t object may be stored.
 *
 * \param[in] user User-provided pointer.
 *
 * \see nmsg_input_open_callback()
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_failure
 * \return #nmsg_res_again
 * \return #nmsg_res_eof
 */
typedef nmsg_res (*nmsg_cb_message_read)(nmsg_message_t *msg, void *user);

#include <nmsg/alias.h>
#include <nmsg/asprintf.h>
#include <nmsg/chalias.h>
#include <nmsg/compat.h>
#include <nmsg/compression.h>
#include <nmsg/constants.h>
#include <nmsg/container.h>
#include <nmsg/filter.h>
#include <nmsg/fltmod.h>
#include <nmsg/input.h>
#include <nmsg/io.h>
#include <nmsg/ipdg.h>
#include <nmsg/message.h>
#include <nmsg/msgmod.h>
#include <nmsg/output.h>
#include <nmsg/pcap_input.h>
#include <nmsg/random.h>
#include <nmsg/rate.h>
#include <nmsg/sock.h>
#include <nmsg/strbuf.h>
#include <nmsg/timespec.h>
#include <nmsg/vendors.h>
#include <nmsg/version.h>
#include <nmsg/zbuf.h>

/**
 * Initialize the libnmsg library. This function MUST be called before
 * using any other libnmsg function. The caller MUST also check that this
 * function returned #nmsg_res_success before using any other libnmsg function.
 * The library should only be initialized once.
 *
 * \return nmsg_res_success On successful library initialization.
 * \return nmsg_res_failure If libnmsg is not usable, or if #nmsg_init() was
 * called more than once.
 */
#if __GNUC__ >= 4
__attribute__ ((warn_unused_result))
#endif
nmsg_res nmsg_init(void);

/**
 * Configure automatic close() behavior of nmsg inputs and outputs. The
 * default behavior is for nmsg_input_close(), nmsg_output_close(), and
 * nmsg_io_destroy() to automatically close the underlying file descriptors
 * for libnmsg inputs and outputs.
 *
 * \param autoclose False to disable automatic close() behavior, true to
 *	re-enable.
 */
void nmsg_set_autoclose(bool autoclose);

/**
 * Set debug level. If the debug level is greater than 0, some libnmsg
 * functions will emit debugging information to stderr. Higher values increase
 * verbosity.
 */
void nmsg_set_debug(int debug);

/**
 * Retrieve the current debug level.
 */
int nmsg_get_debug(void);

/**
 * Retrieve the semantic library version as a string.
 */
const char *nmsg_get_version(void);

/**
 * Retrieve the semantic library version as a packed integer. The number is a
 * combination of the major, minor, and patchelevel numbers as per:
 * MAJOR * 1000000 + MINOR * 1000 + PATCHLEVEL.
 */
uint32_t nmsg_get_version_number(void);
#ifdef __cplusplus
}
#endif

/**
 * Set the NMSG version to use in the output nmsg serialization format.
 * See nmsg/constants.h for the range and default.
 *
 * This is *not* related to nmsg_get_version(), the semantic library version.
 */
void nmsg_output_set_nmsg_version(int nmsg_version);

/**
 * Get the NMSG version to use in the output nmsg serialization format.
 * See nmsg/constants.h for the range and default.
 */
int nmsg_output_get_nmsg_version(void);

/**
\mainpage nmsg documentation

\section intro Introduction

The NMSG format is an efficient encoding of typed, structured data into
payloads which are packed into containers which can be transmitted over the
network or stored to disk. <tt>libnmsg</tt> is the reference implementation of
this format and provides an extensible interface for creating and parsing
messages in NMSG format. The NMSG format relies on Google <a
href="http://code.google.com/p/protobuf/">Protocol Buffers</a> to encode the
payload header. Individual NMSG payloads are distinguished by assigned vendor
ID and message type values and <tt>libnmsg</tt> provides a modular interface
for registering handlers for specific message types. <tt>libnmsg</tt> makes it
easy to build new message types using a <a
href="http://code.google.com/p/protobuf-c/">Protocol Buffers</a> compiler.

\see http://code.google.com/p/protobuf/
\see http://code.google.com/p/protobuf-c/

<hr>

\section libnmsg

<tt>libnmsg</tt> provides a reference C implementation of an NMSG parser and
generator. It contains core functions for reading and writing NMSG units and
can be extended at runtime by plugin modules implementing new message types.

\subsection core Core I/O functions
<div class="subsection">

input.h and output.h provide the single-threaded input and output interfaces.
io.h provides a multi-threaded interface for multiplexing data between inputs
and outputs. message.h provides an interface for creating and inspecting
message payloads.

</div>

\subsection nmsg_msg nmsg_msg message module interface
<div class="subsection">

The <b>nmsg_msg</b> message module interface is implemented by msgmod.h. Plugins
in external shared objects provide an <tt>nmsg_msgmod_t</tt> structure in order
to implement new message types.

</div>

\subsection aux Auxiliary functions
<div class="subsection">

<ul>
<li>alias.h
<li>asprintf.h
<li>chalias.h
<li>ipdg.h
<li>pcap_input.h
<li>rate.h
<li>strbuf.h
<li>timespec.h
<li>zbuf.h
</ul>

</div>

<hr>

\section wire_format Wire format

An NMSG unit consists of a small fixed-length header which precedes a variable
length part that may contain one or more payloads or, if a single payload is too
large, the variable length part may contain a single message fragment.

NMSG is designed for transport over UDP sockets or storage in on-disk files.
Individual UDP datagrams may transport only a single NMSG unit, while the file
format is simply a series of NMSG units concatenated together. The variable
length part of an NMSG unit transported over UDP is usually much smaller than
those stored on disk (#NMSG_WBUFSZ_MAX versus #NMSG_WBUFSZ_JUMBO or
#NMSG_WBUFSZ_ETHER). NMSG units stored on disk also do not contain message
fragments.

The fixed-length NMSG header is ten octets long and consists of a magic value, a
bit field of flags, a protocol version number, and the length of the variable
length data part.

The variable length data part is interpreted as a Protocol Buffer message.

<table>

<tr>
<th>Octet 0-3</th>
<th>Octet 4</th>
<th>Octet 5</th>
<th>Octet 6-9</th>
<th>Remainder</th>
</tr>

<tr>
<td><center>Magic</center></td>
<td><center>Flags</center></td>
<td><center>Protocol Version</center></td>
<td><center>Length</center></td>
<td><center>Data</center></td>
</tr>

</table>

\subsection magic Magic value
<div class="subsection">

The magic value (#NMSG_MAGIC) is always the four octet sequence 'N', 'M', 'S',
'G'.

</div>

\subsection flags Flags
<div class="subsection">

This is a bit field of flags and values.
NMSG_FLAG_FRAGMENT indicates that the data content starts a special fragmentation header.
There is also a bit reserved for future use to indicate the presence of any extended headers.
There are several bits used as a value to indicate any compression-algorithm used.
Previously, only a single bit was used to indicate ZLIB compression, viz, #NMSG_FLAG_ZLIB.

</div>

\subsubsection compression
<div class="subsubsection">

These bits indicates that compression has been applied to the variable
length part. If the #NMSG_FLAG_FRAGMENT flag is not also set, then the entire
variable length part should be deflated with zlib and interpreted as an
<b>NmsgPayload</b>.

</div>

\subsubsection frag NMSG_FLAG_FRAGMENT
<div class="subsubsection">

This flag indicates that the variable length part should be interpreted as an
<b>NmsgFragment</b>. After reassembly, the data should be interpreted as an
<b>NmsgPayload</b>. If any of the compression bits are also set, then the
reassembled data should be deflated and then interpreted as an
<b>NmsgPayload</b>.

Note that when creating a compressed, fragmented NMSG unit, compression should
be applied <i>before</i> fragmentation.

</div>

\subsection version Protocol Version
<div class="subsection">

This value (#NMSG_PROTOCOL_VERSION) is currently 2.

</div>

\subsection length Length
<div class="subsection">

This value is an unsigned 32 bit integer in network byte order indicating the
length in octets of the variable length data part.

</div>

\subsection data Data
<div class="subsection">

The variable length data part is encoded using <a
href="http://code.google.com/apis/protocolbuffers/docs/encoding.html">Google
Protocol Buffers</a>. The file <tt>nmsg/nmsg.proto</tt> in the source
distribution describes the two message types <b>Nmsg</b> and
<b>NmsgFragment</b> that can appear in NMSG units:

\include nmsg.proto

If no flags are set, then the data part is an <b>Nmsg</b> protobuf message. If
only a compression flag is set, then the data part is a compressed
<b>Nmsg</b> protobuf message. The <b>Nmsg</b> protobuf message is a container
message for one or more <b>NmsgPayload</b> messages. If only the
#NMSG_FLAG_FRAGMENT flag is set, then the data part is an <b>NmsgFragment</b>
protobuf message.

</div>

\subsubsection nmsg Nmsg and NmsgPayload protobuf messages
<div class="subsubsection">

<b>Nmsg</b> messages contain one or more <b>NmsgPayload</b> messages.

The <b>vid</b> field of <b>NmsgPayload</b> messages is the vendor ID. The
currently defined vendor IDs are listed in vendors.h and assigned by Farsight.
The <b>msgtype</b> field is a vendor-specific value and together the (<b>vid</b>,
<b>msgtype</b>) tuple defines the type of the data contained in the
<b>payload</b> field.

The time that the data encapsulated in the <b>payload</b> field was generated is
stored in the <b>time_sec</b> and <b>time_nsec</b> fields. The number of
nanoseconds since the Unix epoch is split across the two fields, with the
integer number of seconds stored in the <b>time_sec</b> field and the
nanoseconds part stored in the <b>time_nsec</b> field.

The <b>source</b>, <b>operator</b>, and <b>group</b> fields are optional fields
that can be used by cooperating senders and receivers to classify the payload.

</div>

\subsubsection nmsgfragment NmsgFragment protobuf messages
<div class="subsubsection">

<b>NmsgFragment</b> messages are used to encapsulate fragments of an <b>Nmsg</b>
message if the serialized message is too large for the underlying transport.
This enables NMSG payloads to avoid the size restrictions of UDP/IP transport.

If a serialized <b>Nmsg</b> message is too large for the underlying transport,
it is split into fragments which are carried in the <b>fragment</b> field of a
sequence of <b>NmsgFragment</b> messages. A random value is selected for the
<b>id</b> field of these fragments. The 0-indexed <b>current</b> field indicates
the ordering of the fragments, and the <b>last</b> field indicates the total
number of fragments. Once a receiver has received all the fragments for a given
fragment <b>id</b>, the fragmented payload should be extracted from the
<b>payload</b> field of each fragment and concatenated into a buffer.

If the sender performed compression of the <b>Nmsg</b> message before
fragmentation, then all fragments should have the relevant compression bits set and
the receiver must perform decompression of the reassembled buffer. The result of
decompression should be interpreted as an <b>Nmsg</b> message.

If the sender did not perform compression before fragmentation, then the buffer
should be directly interpreted as an <b>Nmsg</b> message.

</div>

*/

#endif /* NMSG_H */
