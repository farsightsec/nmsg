/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
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
#include <string.h>

#define ISC_CHECK_NONE 1
#include <isc/list.h>

#include "input.h"
#include "io.h"
#include "io_private.h"
#include "output.h"
#include "payload.h"
#include "time.h"

/* Export. */

void *
_nmsg_io_thr_nmsg_read(void *user) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;
	struct nmsg_io_thr *iothr;
	unsigned i;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	iobuf = ISC_LIST_HEAD(io->w_nmsg);
	iopres = ISC_LIST_HEAD(io->w_pres);
	nmsg = NULL;

	if (io->debug >= 4)
		fprintf(stderr, "nmsg_io: started nmsg thread @ %p\n", iothr);

	for (;;) {
		res = nmsg_input_next(iothr->iobuf->buf, &nmsg);
		if (io->stop == true) {
			if (nmsg != NULL) {
				nmsg__nmsg__free_unpacked(nmsg, NULL);
				nmsg = NULL;
			}
			break;
		}
		if (res == nmsg_res_again)
			continue;
		if (res != nmsg_res_success)
			break;

		iothr->count_nmsg_in += 1;
		iothr->count_nmsg_payload_in += nmsg->n_payloads;
		nmsg_time_get(&iothr->now);

		if (io->output_mode == nmsg_io_output_mode_stripe) {
			if (iopres != NULL) {
				if ((res = _nmsg_io_write_pres(iothr, iopres,
							       nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
				iopres = ISC_LIST_NEXT(iopres, link);
				if (iopres == NULL)
					iopres = ISC_LIST_HEAD(io->w_pres);
			}
			if (iobuf != NULL) {
				if ((res = _nmsg_io_write_nmsg(iothr, iobuf,
							       nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
				iobuf = ISC_LIST_NEXT(iobuf, link);
				if (iobuf == NULL)
					iobuf = ISC_LIST_HEAD(io->w_nmsg);

				nmsg->n_payloads = 0;
			}
		} else if (io->output_mode == nmsg_io_output_mode_mirror) {
			for (iopres = ISC_LIST_HEAD(io->w_pres);
			     iopres != NULL;
			     iopres = ISC_LIST_NEXT(iopres, link))
			{
				if ((res = _nmsg_io_write_pres(iothr, iopres,
							       nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
			}
			for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
			     iobuf != NULL;
			     iobuf = ISC_LIST_NEXT(iobuf, link))
			{
				if ((res = _nmsg_io_write_nmsg_dup(iothr, iobuf,
								   nmsg))
				    != nmsg_res_success)
				{
					iothr->res = res;
					goto thr_nmsg_end;
				}
			}
		}
		nmsg__nmsg__free_unpacked(nmsg, NULL);
		nmsg = NULL;
	}
thr_nmsg_end:
	if (nmsg != NULL) {
		if (iothr->res == nmsg_res_stop) {
			for (i = 0; i < nmsg->n_payloads; i++)
				if (nmsg->payloads[i] != NULL)
					nmsg_payload_free(&nmsg->payloads[i]);
		}
		for (i = 0; i < nmsg->n_payloads; i++)
			nmsg->payloads[i] = NULL;
		nmsg->n_payloads = 0;
		nmsg__nmsg__free_unpacked(nmsg, NULL);
	}
	if (io->debug >= 2)
		fprintf(stderr, "nmsg_io: iothr=%p"
			" count_nmsg_in=%" PRIu64
			" count_nmsg_payload_in=%" PRIu64
			"\n",
			iothr,
			iothr->count_nmsg_in,
			iothr->count_nmsg_payload_in);
	return (NULL);
}
