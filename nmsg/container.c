/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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

/* Export. */

struct nmsg_container *
_nmsg_container_init(size_t bufsz, bool do_sequence) {
	struct nmsg_container *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return (NULL);

	c->nmsg = calloc(1, sizeof(Nmsg__Nmsg));
	if (c->nmsg == NULL) {
		free(c);
		return (NULL);
	}
	nmsg__nmsg__init(c->nmsg);

	c->bufsz = bufsz;
	if (c->bufsz < NMSG_WBUFSZ_MIN) {
		_nmsg_container_destroy(&c);
		return (NULL);
	}
	c->estsz = NMSG_HDRLSZ_V2;
	c->do_sequence = do_sequence;

	return (c);
}

void
_nmsg_container_destroy(struct nmsg_container **c) {
	if (*c != NULL) {
		nmsg__nmsg__free_unpacked((*c)->nmsg, NULL);
		free(*c);
		*c = NULL;
	}
}

nmsg_res
_nmsg_container_add(struct nmsg_container *c, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	size_t np_len;
	void *tmp;

	assert(msg->np != NULL);

	/* calculate size of serialized payload */
	np_len = _nmsg_payload_size(msg->np);

	/* check for overflow */
	if (c->estsz != NMSG_HDRLSZ_V2 && c->estsz + np_len + 32 >= c->bufsz)
		return (nmsg_res_container_full);

	/* allocate payload pointer */
	tmp = c->nmsg->payloads;
	c->nmsg->payloads = realloc(c->nmsg->payloads,
				    ++(c->nmsg->n_payloads) * sizeof(void *));
	if (c->nmsg->payloads == NULL) {
		c->nmsg->payloads = tmp;
		return (nmsg_res_memfail);
	}

	/* detach payload from msg object */
	np = msg->np;
	msg->np = NULL;

	/* add payload to container */
	c->nmsg->payloads[c->nmsg->n_payloads - 1] = np;

	/* update estsz */
	c->estsz += np_len;
	/* payload field tag, length */
	c->estsz += 1+1;
	c->estsz += ((np_len >= (1 << 7)) ? 1 : 0);
	c->estsz += ((np_len >= (1 << 14)) ? 1 : 0);
	c->estsz += ((np_len >= (1 << 21)) ? 1 : 0);
	/* crc field */
	c->estsz += 6;
	/* sequence field, sequence_id field */
	c->estsz += (c->do_sequence ? (6+12) : 0);

	/* check if container may need to be fragmented */
	if (c->estsz > c->bufsz)
		return (nmsg_res_container_overfull);

	return (nmsg_res_success);
}

size_t
_nmsg_container_get_num_payloads(struct nmsg_container *c) {
	return (c->nmsg->n_payloads);
}

nmsg_res
_nmsg_container_serialize(struct nmsg_container *c, uint8_t **pbuf, size_t *buf_len,
			  bool do_header, bool do_zlib,
			  uint32_t sequence, uint64_t sequence_id)
{
	static const char magic[] = NMSG_MAGIC;
	size_t len = 0;
	uint8_t flags;
	uint8_t *buf;
	uint8_t *len_wire;
	uint16_t version;

	*pbuf = buf = malloc((do_zlib) ? (2 * c->estsz) : (c->estsz));
	if (buf == NULL)
		return (nmsg_res_memfail);

	if (do_header) {
		/* serialize header */
		memcpy(buf, magic, sizeof(magic));
		buf += sizeof(magic);
		flags = (do_zlib) ? NMSG_FLAG_ZLIB : 0;
		version = NMSG_VERSION | (flags << 8);
		version = htons(version);
		memcpy(buf, &version, sizeof(version));
		buf += sizeof(version);
		
		/* save location where length of serialized NMSG container will be written */
		len_wire = buf;
		buf += sizeof(uint32_t);
	}

	/* calculate payload CRCs */
	_nmsg_payload_calc_crcs(c->nmsg);

	if (c->do_sequence) {
		c->nmsg->sequence = sequence;
		c->nmsg->sequence_id = sequence_id;
		c->nmsg->has_sequence = true;
		c->nmsg->has_sequence_id = true;
	}

	/* serialize the container */
	if (do_zlib == false) {
		len = nmsg__nmsg__pack(c->nmsg, buf);
	} else {
		nmsg_res res;
		nmsg_zbuf_t zbuf;
		size_t ulen;
		u_char *zb_tmp;

		zb_tmp = malloc(c->estsz);
		if (zb_tmp == NULL) {
			free(*pbuf);
			return (nmsg_res_memfail);
		}

		zbuf = nmsg_zbuf_deflate_init();
		if (zbuf == NULL) {
			free(zb_tmp);
			free(*pbuf);
			return (nmsg_res_memfail);
		}

		ulen = nmsg__nmsg__pack(c->nmsg, zb_tmp);
		len = 2 * c->estsz;
		res = nmsg_zbuf_deflate(zbuf, ulen, zb_tmp, &len, buf);
		nmsg_zbuf_destroy(&zbuf);
		free(zb_tmp);
		if (res != nmsg_res_success)
			return (res);
	}

	if (do_header) {
		/* write the length of the container data */
		store_net32(len_wire, len);
		*buf_len = NMSG_HDRLSZ_V2 + len;
	} else {
		*buf_len = len;
	}
	
	if (_nmsg_global_debug >= 6)
		fprintf(stderr, "%s: buf= %p len= %zd\n", __func__, buf, len);

	return (nmsg_res_success);
}

nmsg_res
nmsg_container_deserialize(uint8_t *buf, size_t buf_len,
			   nmsg_message_t **msgarray, size_t *n_msg)
{
	Nmsg__Nmsg *nmsg;
	nmsg_res res;
	ssize_t msgsize;
	unsigned flags;

	/* deserialize the NMSG header */
	res = _input_nmsg_deserialize_header(buf, buf_len, &msgsize, &flags);
	if (res != nmsg_res_success)
		return (res);
	buf += NMSG_HDRLSZ_V2;
	buf_len -= NMSG_HDRLSZ_V2;

	/* the entire NMSG container must be present */
	if ((size_t) msgsize != buf_len)
		return (nmsg_res_failure);

	/* unpack message container */
	res = _input_nmsg_unpack_container2(buf, buf_len, flags, &nmsg);
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
