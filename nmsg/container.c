/*
 * Copyright (c) 2023 DomainTools LLC
 * Copyright (c) 2012, 2018 by Farsight Security, Inc.
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

/* Private declarations. */
VECTOR_GENERATE(payload_vec, Nmsg__NmsgPayload *)

struct nmsg_container {
	size_t		bufsz;
	size_t		estsz;
	payload_vec	c_payloads;
	bool		do_sequence;
};

/* Export. */

struct nmsg_container *
nmsg_container_init(size_t bufsz) {
	struct nmsg_container *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return (NULL);

	c->bufsz = bufsz;
	if ((c->bufsz < NMSG_WBUFSZ_MIN)) {
		nmsg_container_destroy(&c);
		return (NULL);
	}
	payload_vec_reinit((c->bufsz / 256), &c->c_payloads);
	c->estsz = NMSG_HEADER_FIXEDSZ;

	return (c);
}

void
nmsg_container_destroy(struct nmsg_container **c) {
	struct nmsg_container *co = *c;

	if (*c != NULL) {
		*c = NULL;
		for (size_t i = 0; i < payload_vec_size(&co->c_payloads); i++)
			_nmsg_payload_free(&payload_vec_data(&co->c_payloads)[i]);

		free(payload_vec_data(&co->c_payloads));
		free(co);
	}
}

void
nmsg_container_set_sequence(struct nmsg_container *c, bool do_sequence) {
	c->do_sequence = do_sequence;
}

nmsg_res
nmsg_container_add(struct nmsg_container *c, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	size_t np_len;
	size_t seqsz;

	/* ensure that msg->np is up-to-date */
	res = _nmsg_message_serialize(msg);
	if (res != nmsg_res_success)
		return (res);
	assert(msg->np != NULL);

	/* calculate size of serialized payload */
	np_len = _nmsg_payload_size(msg->np);

	/* check for overflow */
	if (c->estsz != NMSG_HEADER_FIXEDSZ && c->estsz + np_len + 32 >= c->bufsz)
		return (nmsg_res_container_full);

	/* detach payload from msg object */
	np = msg->np;
	msg->np = NULL;

	/* add payload to container */
	payload_vec_add(&c->c_payloads, np);

	/* update estsz */
	c->estsz += np_len;
	/* payload field tag, length */
	c->estsz += 1+1;
	c->estsz += ((np_len >= (1 << 7)) ? 1 : 0);
	c->estsz += ((np_len >= (1 << 14)) ? 1 : 0);
	c->estsz += ((np_len >= (1 << 21)) ? 1 : 0);
	/* crc field */
	c->estsz += 6;
	/*
	 * 6+12 = length of protobuf-encoded optional 32-bit "sequence" and
	 * optional 64-bit value "sequence_id" values.
	 */
	seqsz = (c->do_sequence ? (6+12) : 0);

	/* check if container may need to be fragmented */
	if (c->estsz + seqsz > c->bufsz)
		return (nmsg_res_container_overfull);

	return (nmsg_res_success);
}

size_t
nmsg_container_get_num_payloads(struct nmsg_container *c) {
	return payload_vec_size(&c->c_payloads);
}

static nmsg_res
compress_container(Nmsg__Nmsg *nmsg, nmsg_compression_type ztype, int zlevel, size_t estsz, uint8_t *out_buf, size_t *out_len)
{
	nmsg_res res;
	size_t packed_len;
	u_char *packed_buf;

	packed_buf = malloc(estsz);
	if (packed_buf == NULL)
		return (nmsg_res_memfail);

	/* Serialize the container. */
	packed_len = nmsg__nmsg__pack(nmsg, packed_buf);

	/* Perform compression on the serialized container. */
	res = nmsg_compress_level(ztype, zlevel, packed_buf, packed_len, out_buf, out_len);

	free(packed_buf);

	return (res);
}

nmsg_res
nmsg_container_serialize2(struct nmsg_container *c,
			  uint8_t **pbuf, size_t *buf_len,
			  bool do_header,
			  nmsg_compression_type ztype, int zlevel,
			  uint32_t sequence, uint64_t sequence_id, size_t *ret_num_pl)
{
	static const char magic[] = NMSG_MAGIC;
	Nmsg__Nmsg st_nmsg = NMSG__NMSG__INIT; /* Used to pack payloads into a buffer to be serialized. */
	size_t len = 0, buf_left, est_packed_size;
	uint8_t *buf, *alloc_buf;
	uint8_t *len_wire = NULL;
	uint16_t version;
	nmsg_res res = nmsg_res_success;

	/*
	 * Estimated size, include space for sequence info.
	 * 6+12 = length of protobuf-encoded optional 32-bit "sequence" and
	 * optional 64-bit value "sequence_id" values.
	 */
	est_packed_size = c->estsz + (c->do_sequence ? (6+12) : 0);

	buf_left = ztype == NMSG_COMPRESSION_NONE ? est_packed_size : 2 * est_packed_size;
	alloc_buf = buf = malloc(buf_left);
	if (buf == NULL)
		return (nmsg_res_memfail);

	/* The container holds/owns the payloads. */
	st_nmsg.payloads = payload_vec_data(&c->c_payloads);
	st_nmsg.n_payloads = payload_vec_size(&c->c_payloads);

	if (ret_num_pl != NULL)			/* Return # payloads in container. */
		*ret_num_pl = st_nmsg.n_payloads;

	if (do_header) {
#if NMSG_PROTOCOL_VERSION == 3U
		uint16_t num_payloads;
#endif
		uint8_t flags;

		/* serialize header */
		memcpy(buf, magic, sizeof(magic));
		buf += sizeof(magic);

#if NMSG_PROTOCOL_VERSION == 3U
		flags = NMSG_COMPRESSION_TO_FLAG_V3(ztype);
#else
		flags = NMSG_COMPRESSION_TO_FLAG_V2(ztype);
#endif

		version = nmsg_output_get_nmsg_version() | (flags << 8);
		version = htons(version);
		memcpy(buf, &version, sizeof(version));
		buf += sizeof(version);

#if NMSG_PROTOCOL_VERSION == 3U
		/*
		 * Payload-count maxes out at 0xffff,
		 * 0xffff can mean more than 0xffff.
		 */
		num_payloads = st_nmsg.n_payloads > 0xFFFF ? 0xFFFF
			: st_nmsg.n_payloads & 0xFFFF;
		num_payloads = htons(num_payloads);
		memcpy(buf, &num_payloads, sizeof(num_payloads));
		buf += sizeof(num_payloads);
#endif
		/* save location where length of serialized NMSG container will be written */
		len_wire = buf;
		buf += sizeof(uint32_t);

		buf_left -= NMSG_HEADER_FIXEDSZ;
	}

	/* calculate payload CRCs */
	_nmsg_payload_calc_crcs(&st_nmsg);		/* This allocates memory -- must be free'd. */

	if (c->do_sequence) {
		st_nmsg.sequence = sequence;
		st_nmsg.sequence_id = sequence_id;
		st_nmsg.has_sequence = true;
		st_nmsg.has_sequence_id = true;
	}

	/* serialize the container */
	if (ztype == NMSG_COMPRESSION_NONE) {
		len = nmsg__nmsg__pack(&st_nmsg, buf);
		res = nmsg_res_success;
	} else {
		len = buf_left;				/* This is an in/out parameter. */
		res = compress_container(&st_nmsg, ztype, zlevel, est_packed_size, buf, &len);
	}

	_nmsg_payload_free_crcs(&st_nmsg);		/* Release any CRC allocations. */

	if (res == nmsg_res_success) {
		*pbuf = alloc_buf;
		if (do_header) {
			/* write the length of the container data */
			store_net32(len_wire, len);
			*buf_len = NMSG_HEADER_FIXEDSZ + len;
		} else
			*buf_len = len;

		_nmsg_dprintf(6, "%s: buf= %p len= %zd\n", __func__, buf, len);
	} else
		free(alloc_buf);

	return (res);
}

/* This is the older interface that supports only ZLIB compression. */
nmsg_res
nmsg_container_serialize(struct nmsg_container *c,
			 uint8_t **pbuf, size_t *buf_len,
			 bool do_header, bool do_zlib,
			 uint32_t sequence, uint64_t sequence_id)
{
	return (nmsg_container_serialize2(c, pbuf, buf_len, do_header,
				  do_zlib ? NMSG_COMPRESSION_ZLIB : NMSG_COMPRESSION_NONE, 9,
				  sequence, sequence_id, NULL));
}

nmsg_res
nmsg_container_deserialize(const uint8_t *buf, size_t buf_len,
			   nmsg_message_t **msgarray, size_t *n_msg)
{
	struct nmsg_header hdr;
	Nmsg__Nmsg *nmsg;
	nmsg_res res;

	/* deserialize the NMSG header */
	res = _input_nmsg_extract_header(buf, buf_len, &hdr);
	if (res != nmsg_res_success)
		return (res);

	buf += hdr.h_header_size;
	buf_len -= hdr.h_header_size;

	/* the entire NMSG container must be present */
	if ((size_t) hdr.h_msgsize != buf_len)
		return (nmsg_res_failure);

	/* unpack message container */
	res = _input_nmsg_unpack_container2(buf, buf_len, &hdr, &nmsg);
	if (res != nmsg_res_success)
		return (res);

	if (nmsg != NULL) {
		*msgarray = malloc(nmsg->n_payloads * sizeof(void *));
		if (*msgarray == NULL) {
			nmsg__nmsg__free_unpacked(nmsg, NULL);
			return (nmsg_res_memfail);
		}
		*n_msg = nmsg->n_payloads;

		for (unsigned i = 0; i < nmsg->n_payloads; i++) {
			Nmsg__NmsgPayload *np;
			nmsg_message_t msg;

			/* detach payload */
			np = nmsg->payloads[i];
			nmsg->payloads[i] = NULL;

			/* convert payload to message object */
			msg = _nmsg_message_from_payload(np);
			if (msg == NULL) {
				free(*msgarray);
				*msgarray = NULL;
				*n_msg = 0;
				nmsg__nmsg__free_unpacked(nmsg, NULL);
				return (nmsg_res_memfail);
			}
			(*msgarray)[i] = msg;
		}
		nmsg->n_payloads = 0;
		free(nmsg->payloads);
		nmsg->payloads = NULL;
		nmsg__nmsg__free_unpacked(nmsg, NULL);
	}

	return (nmsg_res_success);
}
