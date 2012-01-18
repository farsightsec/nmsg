/*
 * Copyright (c) 2008-2012 by Internet Systems Consortium, Inc. ("ISC")
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

/* Import. */

#include "private.h"

/* Forward. */
static void	header_serialize(uint8_t *buf, uint8_t flags, uint32_t len);

/* Internal functions. */

nmsg_res
_output_frag_write(nmsg_output_t output) {
	Nmsg__NmsgFragment nf;
	int i;
	nmsg_res res;
	size_t len, fragpos, fragsz, fraglen, max_fragsz;
	uint8_t flags = 0, *packed, *frag_packed, *frag_packed_container;

	assert(output->type == nmsg_output_type_stream);

	nmsg__nmsg_fragment__init(&nf);
	max_fragsz = output->stream->bufsz - 32;

	res = _nmsg_container_serialize(output->stream->c,
					&packed,
					&len,
					false, /* do_header */
					output->stream->do_zlib,
					output->stream->sequence,
					output->stream->sequence_id
	);
	if (output->stream->do_sequence)
		output->stream->sequence += 1;

	if (output->stream->do_zlib)
		flags |= NMSG_FLAG_ZLIB;

	if (res != nmsg_res_success)
		return (res);

	if (output->stream->do_zlib && len <= max_fragsz) {
		/* write out the unfragmented NMSG container */

		if (output->stream->type == nmsg_stream_type_sock) {
			res = _output_nmsg_write_sock(output, packed, len);
		} else if (output->stream->type == nmsg_stream_type_file) {
			res = _output_nmsg_write_file(output, packed, len);
		} else if (output->stream->type == nmsg_stream_type_zmq) {
			assert(0);
		}
		goto frag_out;
	}

	/* allocate a buffer large enough to hold one serialized fragment */
	frag_packed = malloc(NMSG_HDRLSZ_V2 + output->stream->bufsz + 32);
	if (frag_packed == NULL) {
		res = nmsg_res_memfail;
		goto frag_out;
	}
	frag_packed_container = frag_packed + NMSG_HDRLSZ_V2;

	/* create and send fragments */
	flags |= NMSG_FLAG_FRAGMENT;
	nf.id = nmsg_random_uint32(output->stream->random);
	nf.last = len / max_fragsz;
	nf.crc = nmsg_crc32c(packed, len);
	nf.has_crc = true;
	for (fragpos = 0, i = 0;
	     fragpos < len;
	     fragpos += max_fragsz, i++)
	{
		/* serialize the fragment */
		nf.current = i;
		fragsz = (len - fragpos > max_fragsz) ? max_fragsz : (len - fragpos);
		nf.fragment.len = fragsz;
		nf.fragment.data = packed + fragpos;
		fraglen = nmsg__nmsg_fragment__pack(&nf, frag_packed_container);
		header_serialize(frag_packed, flags, fraglen);
		fraglen += NMSG_HDRLSZ_V2;

		/* send the serialized fragment */
		if (output->stream->type == nmsg_stream_type_sock) {
			res = _output_nmsg_write_sock(output, frag_packed, fraglen);
			free(frag_packed);
		} else if (output->stream->type == nmsg_stream_type_file) {
			res = _output_nmsg_write_file(output, frag_packed, fraglen);
			free(frag_packed);
		} else if (output->stream->type == nmsg_stream_type_zmq) {
			res = _output_nmsg_write_zmq(output, frag_packed, fraglen);
		} else {
			assert(0);
		}
	}

frag_out:
	free(packed);
	_nmsg_container_destroy(&output->stream->c);
	output->stream->c = _nmsg_container_init(output->stream->bufsz,
						 output->stream->do_sequence);
	if (output->stream->c == NULL)
		return (nmsg_res_memfail);
	return (res);
}

static void
header_serialize(uint8_t *buf, uint8_t flags, uint32_t len) {
	static const char magic[] = NMSG_MAGIC;
	uint16_t version;

	memcpy(buf, magic, sizeof(magic));
	buf += sizeof(magic);

	version = NMSG_VERSION | (flags << 8);
	store_net16(buf, version);

	buf += sizeof(version);
	store_net32(buf, len);
}
