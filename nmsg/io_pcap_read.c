/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#include "nmsg_port.h"

#include <pthread.h>
#include <stdlib.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "io.h"
#include "io_private.h"
#include "input.h"
#include "payload.h"
#include "time.h"

/* Export. */

void *
_nmsg_io_thr_pcap_read(void *user) {
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pcap *iopcap;
	struct nmsg_io_thr *iothr;
	//void *clos;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	iobuf = ISC_LIST_HEAD(io->w_nmsg);
	iopcap = iothr->iopcap;
	np = NULL;

	if (io->debug >= 4)
		fprintf(stderr, "nmsg_io: started pcap thread @ %p\n", iothr);

	/* initialize thread-local instance of pcap dgram-to-pbuf module */
#if 0
	res = nmsg_pbmod_init(iopcap->mod, &clos, io->debug);
	if (res != nmsg_res_success)
		return (NULL);
#endif

	/* stop if there are no nmsg sinks available */
	if (iobuf == NULL) {
		fprintf(stderr, "nmsg_io: no nmsg outputs\n");
		goto thr_pcap_end;
	}

	for (;;) {
		struct nmsg_ipdg dg;

		if (io->stop == true)
			goto thr_pcap_end;

		res = nmsg_input_next_pcap(iopcap->pcap, &dg);
		if (res == nmsg_res_again) {
			/* nmsg_input_next_pcap() only returns nmsg_res_again
			 * when a fragment is consumed, but this still counts
			 * as an input packet */
			iothr->count_pcap_in += 1;
			continue;
		}
		if (res != nmsg_res_success) {
			iothr->res = res;
			goto thr_pcap_end;
		}

		/* increment pcap counters */
		iothr->count_pcap_in += 1;
		iothr->count_pcap_datagram_in += 1;
	}
#if 0
		res = nmsg_pbmod_pres_to_pbuf(iopres->mod, iopres->clos, line);
		if (res == nmsg_res_failure) {
			iothr->res = res;
			goto thr_pcap_end;
		}
		if (res == nmsg_res_success)
			continue;
		if (res != nmsg_res_pbuf_ready) {
			iothr->res = res;
			goto thr_pcap_end;
		}

		res = nmsg_pbmod_pres_to_pbuf_finalize(iopres->mod,
						       iopres->clos,
						       &pbuf, &sz);
		if (res != nmsg_res_success) {
			iothr->res = res;
			goto thr_pcap_end;
		}

		nmsg_time_get(&iothr->now);
		iothr->count_pres_payload_in += 1;
		np = _nmsg_io_make_nmsg_payload(iothr, pbuf, sz);
		if (np == NULL) {
			free(pbuf);
			iothr->res = nmsg_res_memfail;
			goto thr_pcap_end;
		}

		if (io->output_mode == nmsg_io_output_mode_stripe) {
			pthread_mutex_lock(&iobuf->lock);
			res = _nmsg_io_write_nmsg_payload(iothr, iobuf, np);
			pthread_mutex_unlock(&iobuf->lock);
			if (res != nmsg_res_success) {
				iothr->res = res;
				goto thr_pcap_end;
			}

			iobuf = ISC_LIST_NEXT(iobuf, link);
			if (iobuf == NULL)
				iobuf = ISC_LIST_HEAD(io->w_nmsg);
		} else if (io->output_mode == nmsg_io_output_mode_mirror) {
			for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
			     iobuf != NULL;
			     iobuf = ISC_LIST_NEXT(iobuf, link))
			{
				Nmsg__NmsgPayload *npdup;

				npdup = nmsg_payload_dup(np);
				if (npdup == NULL) {
					iothr->res = nmsg_res_memfail;
					goto thr_pcap_end;
				}

				pthread_mutex_lock(&iobuf->lock);
				res = _nmsg_io_write_nmsg_payload(iothr, iobuf,
								  npdup);
				pthread_mutex_unlock(&iobuf->lock);
				if (res != nmsg_res_success) {
					iothr->res = res;
					goto thr_pcap_end;
				}
			}
			nmsg_payload_free(&np);
		}
	}
#endif
thr_pcap_end:
	//nmsg_pbmod_fini(iopcap->mod, &clos);
	if (io->debug >= 2)
		fprintf(stderr, "nmsg_io: iothr=%p"
			" count_pcap_in=%" PRIu64
			" count_pcap_payload_in=%" PRIu64
			"\n",
			iothr,
			iothr->count_pcap_in,
			iothr->count_pcap_datagram_in);
	return (NULL);
}
