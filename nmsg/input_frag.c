/*
 * Copyright (c) 2009, 2011, 2012 by Farsight Security, Inc.
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

/* Import. */

#include "private.h"
#include "libmy/tree.h"

/* Forward. */

static nmsg_res reassemble_frags(nmsg_input_t, Nmsg__Nmsg **, struct nmsg_frag *);

/* Red-black nmsg_frag glue. */

static int
frag_cmp(struct nmsg_frag *e1, struct nmsg_frag *e2) {
	return (memcmp(&e1->key, &e2->key, sizeof(struct nmsg_frag_key)));
}

RB_PROTOTYPE(frag_ent, nmsg_frag, link, frag_cmp)
RB_GENERATE(frag_ent, nmsg_frag, link, frag_cmp)

/* Convenience macros. */

#define FRAG_INSERT(stream, fent) do { \
	RB_INSERT(frag_ent, &((stream)->nft.head), fent); \
} while(0)

#define FRAG_FIND(stream, fent, find) do { \
	fent = RB_FIND(frag_ent, &((stream)->nft.head), find); \
} while(0)

#define FRAG_REMOVE(stream, fent) do { \
	RB_REMOVE(frag_ent, &((stream)->nft.head), fent); \
} while(0)

#define FRAG_NEXT(stream, fent, fent_next) do { \
	fent_next = RB_NEXT(frag_ent, &((stream)->nft.head), fent); \
} while(0)

/* Internal functions. */

nmsg_res
_input_frag_read(nmsg_input_t input, Nmsg__Nmsg **nmsg, uint8_t *buf, size_t buf_len) {
	Nmsg__NmsgFragment *nfrag;
	nmsg_res res;
	struct nmsg_frag *fent, find;

	res = nmsg_res_again;

	nfrag = nmsg__nmsg_fragment__unpack(NULL, buf_len, buf);
	if (nfrag == NULL)
		return (nmsg_res_parse_error);

	/* find the fragment, else allocate a node and insert into the tree */
	memset(&find, 0, sizeof(find));
	find.key.id = nfrag->id;
	find.key.crc = nfrag->crc;
	memcpy(&find.key.addr_ss, &input->stream->addr_ss, sizeof(input->stream->addr_ss));

	FRAG_FIND(input->stream, fent, &find);
	if (fent == NULL) {
		fent = calloc(1, sizeof(*fent));
		if (fent == NULL) {
			res = nmsg_res_memfail;
			goto read_input_frag_out;
		}
		fent->key.id = nfrag->id;
		fent->key.crc = nfrag->crc;
		memcpy(&fent->key.addr_ss, &input->stream->addr_ss, sizeof(input->stream->addr_ss));
		fent->last = nfrag->last;
		fent->rem = nfrag->last + 1;
		fent->ts = input->stream->now;
		fent->frags = calloc(1, sizeof(ProtobufCBinaryData) *
				     (fent->last + 1));
		if (fent->frags == NULL) {
			free(fent);
			res = nmsg_res_memfail;
			goto read_input_frag_out;
		}
		FRAG_INSERT(input->stream, fent);
		input->stream->nfrags += 1;
	} else {
		assert(fent->last == nfrag->last);
	}

	if (fent->frags[nfrag->current].data != NULL) {
		/* fragment has already been received, network problem? */
		goto read_input_frag_out;
	}

	/* attach the fragment payload to the tree node */
	fent->frags[nfrag->current] = nfrag->fragment;

	/* decrement number of remaining fragments */
	fent->rem -= 1;

	/* detach the fragment payload from the NmsgFragment */
	nfrag->fragment.len = 0;
	nfrag->fragment.data = NULL;

	/* reassemble if all the fragments have been gathered */
	if (fent->rem == 0)
		res = reassemble_frags(input, nmsg, fent);

read_input_frag_out:
	nmsg__nmsg_fragment__free_unpacked(nfrag, NULL);
	return (res);
}

void
_input_frag_destroy(struct nmsg_stream_input *stream) {
	struct nmsg_frag *fent, *fent_next;
	unsigned i;

	for (fent = RB_MIN(frag_ent, &(stream->nft.head));
	     fent != NULL;
	     fent = fent_next)
	{
		FRAG_NEXT(stream, fent, fent_next);
		for (i = 0; i <= fent->last; i++)
			free(fent->frags[i].data);
		free(fent->frags);
		FRAG_REMOVE(stream, fent);
		free(fent);
	}
}

void
_input_frag_gc(struct nmsg_stream_input *stream) {
	struct nmsg_frag *fent, *fent_next;
	unsigned i;

	if (!(stream->nfrags > 0 &&
	      stream->now.tv_sec - stream->lastgc.tv_sec >= NMSG_FRAG_GC_INTERVAL))
	{
		return;
	}

	for (fent = RB_MIN(frag_ent, &(stream->nft.head));
	     fent != NULL;
	     fent = fent_next)
	{
		FRAG_NEXT(stream, fent, fent_next);
		if (stream->now.tv_sec - fent->ts.tv_sec >=
		    NMSG_FRAG_GC_INTERVAL)
		{
			FRAG_NEXT(stream, fent, fent_next);
			for (i = 0; i <= fent->last; i++)
				free(fent->frags[i].data);
			free(fent->frags);
			FRAG_REMOVE(stream, fent);
			free(fent);
			stream->nfrags -= 1;
		}
	}

	stream->lastgc = stream->now;
}

/* Private functions. */

static nmsg_res
reassemble_frags(nmsg_input_t input, Nmsg__Nmsg **nmsg, struct nmsg_frag *fent) {
	nmsg_res res;
	size_t len, padded_len;
	uint8_t *payload, *ptr;
	unsigned i;

	/* obtain total length of reassembled payload */
	len = 0;
	for (i = 0; i <= fent->last; i++) {
		assert(fent->frags[i].data != NULL);
		len += fent->frags[i].len;
	}

	/* round total length up to nearest kilobyte */
	padded_len = len;
	if (len % 1024 != 0)
		padded_len += 1024 - (len % 1024);

	ptr = payload = malloc(padded_len);
	if (payload == NULL) {
		return (nmsg_res_memfail);
	}

	/* copy into the payload buffer and deallocate frags */
	for (i = 0; i <= fent->last; i++) {
		memcpy(ptr, fent->frags[i].data, fent->frags[i].len);
		free(fent->frags[i].data);
		ptr += fent->frags[i].len;
	}
	free(fent->frags);

	/* decompress */
	if (input->stream->flags & NMSG_FLAG_ZLIB) {
		size_t u_len;
		u_char *u_buf, *z_buf;

		z_buf = (u_char *) payload;
		res = nmsg_zbuf_inflate(input->stream->zb, len, z_buf,
					&u_len, &u_buf);
		if (res != nmsg_res_success) {
			free(payload);
			goto reassemble_frags_out;
		}
		payload = u_buf;
		len = u_len;
		free(z_buf);
	}

	/* unpack the defragmented payload */
	*nmsg = nmsg__nmsg__unpack(NULL, len, payload);
	if (*nmsg != NULL)
		res = nmsg_res_success;
	else
		res = nmsg_res_parse_error;
	free(payload);

reassemble_frags_out:
	/* deallocate from tree */
	input->stream->nfrags -= 1;
	FRAG_REMOVE(input->stream, fent);
	free(fent);

	return (res);
}

