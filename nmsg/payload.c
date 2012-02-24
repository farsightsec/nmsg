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
_nmsg_payload_calc_crcs(Nmsg__Nmsg *nc) {
	unsigned i;

	if (nc->payload_crcs != NULL)
		free(nc->payload_crcs);

	nc->payload_crcs = malloc(nc->n_payloads * sizeof(*(nc->payload_crcs)));
	assert(nc->payload_crcs != NULL);

	for (i = 0; i < nc->n_payloads; i++)
		nc->payload_crcs[i] = htonl(nmsg_crc32c(nc->payloads[i]->payload.data,
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
