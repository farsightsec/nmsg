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

/* Internal functions. */

nmsg_res
_output_frag_write(nmsg_output_t output) {
	Nmsg__Nmsg *nc;
	Nmsg__NmsgFragment nf;
	int i;
	nmsg_res res;
	size_t len, zlen, fragpos, fragsz, fraglen, max_fragsz;
	ssize_t bytes_written;
	struct iovec iov[2];
	uint8_t flags, *packed, *frag_packed;
	struct nmsg_buf *buf;

	buf = output->stream->buf;
	flags = 0;
	nc = output->stream->nmsg;
	nmsg__nmsg_fragment__init(&nf);
	max_fragsz = buf->bufsz - 32;

	_nmsg_payload_calc_crcs(nc);

	/* allocate a buffer large enough to hold the unfragmented nmsg */
	packed = malloc(output->stream->estsz);
	if (packed == NULL)
		return (nmsg_res_memfail);

	if (output->type == nmsg_output_type_stream &&
	    output->stream->type == nmsg_stream_type_sock)
	{
		nc->has_sequence = true;
		nc->sequence = output->stream->sequence;
		output->stream->sequence += 1;

		nc->has_sequence_id = true;
		nc->sequence_id = output->stream->sequence_id;
	}

	len = nmsg__nmsg__pack(nc, packed);

	/* compress the unfragmented nmsg if requested */
	if (output->stream->zb != NULL) {
		uint8_t *zpacked;

		flags = NMSG_FLAG_ZLIB;

		/* allocate a buffer large enough to hold the compressed,
		 * unfragmented nmsg */
		zlen = 2 * output->stream->estsz;
		zpacked = malloc(zlen);
		if (zpacked == NULL) {
			free(packed);
			return (nmsg_res_memfail);
		}

		/* compress the unfragmented nmsg and replace the uncompressed
		 * nmsg with the compressed version */
		res = nmsg_zbuf_deflate(output->stream->zb, len, packed, &zlen,
					zpacked);
		free(packed);
		if (res != nmsg_res_success) {
			free(zpacked);
			return (res);
		}
		packed = zpacked;
		len = zlen;

		/* write out the unfragmented nmsg if it's small enough after
		 * compression */
		if (len <= max_fragsz) {
			_output_nmsg_header_serialize(buf, flags);
			store_net32(buf->pos, len);

			iov[0].iov_base = (void *) buf->data;
			iov[0].iov_len = NMSG_HDRLSZ_V2;
			iov[1].iov_base = (void *) packed;
			iov[1].iov_len = len;

			bytes_written = writev(buf->fd, iov, 2);
			if (bytes_written < 0)
				perror("writev");
			else if (output->stream->type != nmsg_stream_type_sock)
				assert(bytes_written == (ssize_t)
				       (NMSG_HDRLSZ_V2 + len));
			goto frag_out;
		}
	}

	/* allocate a buffer large enough to hold one serialized fragment */
	frag_packed = malloc(buf->bufsz + 32);
	if (frag_packed == NULL)
		goto frag_out;

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
		fragsz = (len - fragpos > max_fragsz)
			? max_fragsz : (len - fragpos);
		nf.fragment.len = fragsz;
		nf.fragment.data = packed + fragpos;
		fraglen = nmsg__nmsg_fragment__pack(&nf, frag_packed);

		/* send the serialized fragment */
		_output_nmsg_header_serialize(buf, flags);
		store_net32(buf->pos, fraglen);

		iov[0].iov_base = (void *) buf->data;
		iov[0].iov_len = NMSG_HDRLSZ_V2;
		iov[1].iov_base = (void *) frag_packed;
		iov[1].iov_len = fraglen;

		bytes_written = writev(buf->fd, iov, 2);
		if (bytes_written < 0)
			perror("writev");
		else if (output->stream->type != nmsg_stream_type_sock)
			assert(bytes_written == (ssize_t)
			       (NMSG_HDRLSZ_V2 + fraglen));
	}
	free(frag_packed);

frag_out:
	free(packed);
	_nmsg_payload_free_all(nc);

	return (nmsg_res_success);
}
