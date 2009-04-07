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

/* Private. */

static void *
_nmsg_io_thr_pres_read(void *user) {
	Nmsg__NmsgPayload *np;
	char line[1024];
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pres *iopres;
	struct nmsg_io_thr *iothr;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	iobuf = ISC_LIST_HEAD(io->w_nmsg);
	iopres = iothr->iopres;
	np = NULL;

	res = nmsg_pbmod_init(iopres->mod, &iopres->clos, io->debug);
	if (res != nmsg_res_success)
		return (NULL);

	if (iothr->io->debug >= 4)
		fprintf(stderr, "nmsg_io: started pres thread @ %p\n", iothr);

	if (iobuf == NULL) {
		fprintf(stderr, "nmsg_io: no nmsg outputs\n");
		goto thr_pres_end;
	}

	while (fgets(line, sizeof(line), iopres->fp) != NULL) {
		size_t sz;
		uint8_t *pbuf;

		if (io->stop == true)
			goto thr_pres_end;

		iothr->count_pres_in += 1;
		res = nmsg_pbmod_pres_to_pbuf(iopres->mod, iopres->clos, line);
		if (res == nmsg_res_failure) {
			iothr->res = res;
			goto thr_pres_end;
		}
		if (res == nmsg_res_success)
			continue;
		if (res != nmsg_res_pbuf_ready) {
			iothr->res = res;
			goto thr_pres_end;
		}

		res = nmsg_pbmod_pres_to_pbuf_finalize(iopres->mod,
						       iopres->clos,
						       &pbuf, &sz);
		if (res != nmsg_res_success) {
			iothr->res = res;
			goto thr_pres_end;
		}

		nmsg_timespec_get(&iothr->now);
		iothr->count_pres_payload_in += 1;
		np = _nmsg_io_make_nmsg_payload(iothr, pbuf, sz,
						iopres->pres->vid,
						iopres->pres->msgtype);
		if (np == NULL) {
			free(pbuf);
			iothr->res = nmsg_res_memfail;
			goto thr_pres_end;
		}

		if (io->output_mode == nmsg_io_output_mode_stripe) {
			pthread_mutex_lock(&iobuf->lock);
			res = _nmsg_io_write_nmsg_payload(iothr, iobuf, np);
			pthread_mutex_unlock(&iobuf->lock);
			if (res != nmsg_res_success) {
				iothr->res = res;
				goto thr_pres_end;
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
					goto thr_pres_end;
				}

				pthread_mutex_lock(&iobuf->lock);
				res = _nmsg_io_write_nmsg_payload(iothr, iobuf,
								  npdup);
				pthread_mutex_unlock(&iobuf->lock);
				if (res != nmsg_res_success) {
					iothr->res = res;
					goto thr_pres_end;
				}
			}
			nmsg_payload_free(&np);
		}
	}
thr_pres_end:
	nmsg_pbmod_fini(iopres->mod, &iopres->clos);
	if (io->debug >= 2)
		fprintf(stderr, "nmsg_io: iothr=%p"
			" count_pres_in=%" PRIu64
			" count_pres_payload_in=%" PRIu64
			"\n",
			iothr,
			iothr->count_pres_in,
			iothr->count_pres_payload_in);
	return (NULL);
}
