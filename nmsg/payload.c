/*
 * Copyright (c) 2008-2013 by Farsight Security, Inc.
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

void
_nmsg_payload_free_all(Nmsg__Nmsg *nc) {
	unsigned i;

	for (i = 0; i < nc->n_payloads; i++) {
		nmsg__nmsg_payload__free_unpacked(nc->payloads[i], NULL);
		nc->payloads[i] = NULL;
	}
	nc->n_payloads = 0;
}

void
_nmsg_payload_free_crcs(Nmsg__Nmsg *nc)
{
	if (nc->payload_crcs != NULL) {
		free(nc->payload_crcs);
		nc->payload_crcs = NULL;
		nc->n_payload_crcs = 0;
	}
}

void
_nmsg_payload_calc_crcs(Nmsg__Nmsg *nc) {
	unsigned i;

	_nmsg_payload_free_crcs(nc);

	nc->payload_crcs = malloc(nc->n_payloads * sizeof(*(nc->payload_crcs)));
	assert(nc->payload_crcs != NULL);

	for (i = 0; i < nc->n_payloads; i++)
		nc->payload_crcs[i] = htonl(my_crc32c(nc->payloads[i]->payload.data,
						      nc->payloads[i]->payload.len));

	nc->n_payload_crcs = nc->n_payloads;
}

void
_nmsg_payload_free(Nmsg__NmsgPayload **np) {
	nmsg__nmsg_payload__free_unpacked(*np, NULL);
	*np = NULL;
}

size_t
_nmsg_payload_size(const Nmsg__NmsgPayload *np) {
	size_t sz;
	Nmsg__NmsgPayload copy;

	copy = *np;
	copy.payload.len = 0;
	copy.payload.data = NULL;
	sz = nmsg__nmsg_payload__get_packed_size(&copy);

	sz += np->payload.len;

	/* varint encoded length */
	if (np->payload.len >= (1 << 7))
		sz += 1;
	if (np->payload.len >= (1 << 14))
		sz += 1;

	return (sz);
}
