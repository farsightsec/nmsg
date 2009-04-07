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

/* Private. */

static void *
_nmsg_io_thr_pcap_read(void *user) {
	Nmsg__NmsgPayload *np = NULL, *npdup = NULL;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_buf *iobuf;
	struct nmsg_io_pcap *iopcap;
	struct nmsg_io_pres *iopres;
	struct nmsg_io_thr *iothr;
	void *clos;

	iothr = (struct nmsg_io_thr *) user;
	io = iothr->io;
	iopcap = iothr->iopcap;
	iobuf = ISC_LIST_HEAD(io->w_nmsg);
	iopres = ISC_LIST_HEAD(io->w_pres);

	if (io->debug >= 4)
		fprintf(stderr, "nmsg_io: started pcap thread @ %p\n", iothr);

	/* initialize thread-local instance of pcap dgram-to-pbuf module */
	res = nmsg_pbmod_init(iopcap->mod, &clos, io->debug);
	if (res != nmsg_res_success)
		return (NULL);

	for (;;) {
		struct nmsg_ipdg dg;
		size_t sz;
		uint8_t *pbuf;
		unsigned vid, msgtype;

		if (io->stop == true)
			break;

		/* get next ip datagram from pcap source */
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
			break;
		}

		/* convert ip datagram to protobuf payload */
		res = nmsg_pbmod_ipdg_to_pbuf(iopcap->mod, clos, &dg,
					      &pbuf, &sz, &vid, &msgtype);
		if (res == nmsg_res_failure) {
			iothr->res = res;
			break;
		}
		if (res != nmsg_res_pbuf_ready) {
			iothr->res = res;
			break;
		}

		/* increment pcap counters */
		iothr->count_pcap_in += 1;
		iothr->count_pcap_datagram_in += 1;

		/* convert protobuf payload to nmsg payload */
		nmsg_time_get(&iothr->now);
		np = _nmsg_io_make_nmsg_payload(iothr, pbuf, sz,
						vid, msgtype);
		if (np == NULL) {
			free(pbuf);
			iothr->res = nmsg_res_memfail;
			break;
		}

		/* striped iobuf output */
		if (io->output_mode == nmsg_io_output_mode_stripe &&
		    iobuf != NULL)
		{
			/* write out nmsg payload */
			pthread_mutex_lock(&iobuf->lock);
			res = _nmsg_io_write_nmsg_payload(iothr, iobuf, np);
			pthread_mutex_unlock(&iobuf->lock);
			if (res != nmsg_res_success) {
				iothr->res = res;
				break;
			}
			/* advance to next iobuf in list */
			iobuf = ISC_LIST_NEXT(iobuf, link);
			if (iobuf == NULL)
				iobuf = ISC_LIST_HEAD(io->w_nmsg);
		}

		/* striped iopres output */
		if (io->output_mode == nmsg_io_output_mode_stripe &&
		    iopres != NULL)
		{
			/* write out pres form of payload */
			pthread_mutex_lock(&iopres->lock);
			res = _nmsg_io_write_pres_payload(iothr, iopres, np);
			pthread_mutex_unlock(&iopres->lock);
			if (res != nmsg_res_success) {
				iothr->res = res;
				break;
			}
			/* advance to next iopres in list */
			iopres = ISC_LIST_NEXT(iopres, link);
			if (iopres == NULL)
				iopres = ISC_LIST_HEAD(io->w_pres);
		}

		/* mirrored iobuf/iopres output */
		if (io->output_mode == nmsg_io_output_mode_mirror) {
			for (iopres = ISC_LIST_HEAD(io->w_pres);
			     iopres != NULL;
			     iopres = ISC_LIST_NEXT(iopres, link))
			{
				res = _nmsg_io_write_pres_payload(iothr, iopres,
								  np);
				if (res != nmsg_res_success) {
					iothr->res = res;
					break;
				}
			}
			for (iobuf = ISC_LIST_HEAD(io->w_nmsg);
			     iobuf != NULL;
			     iobuf = ISC_LIST_NEXT(iobuf, link))
			{
				/* duplicate payload */
				npdup = nmsg_payload_dup(np);
				if (npdup == NULL) {
					iothr->res = nmsg_res_memfail;
					break;
				}

				/* write out nmsg payload */
				pthread_mutex_lock(&iobuf->lock);
				res = _nmsg_io_write_nmsg_payload(iothr, iobuf,
								  npdup);
				pthread_mutex_unlock(&iobuf->lock);
				if (res != nmsg_res_success) {
					iothr->res = res;
					break;
				}
			}
			/* if we are mirroring across our iobuf outputs, then
			 * the original copy of the payload was never added to
			 * an nmsg output, so deallocate the original here */
			nmsg_payload_free(&np);
		}

		/* if we have no iobuf outputs (i.e. pres outputs only) then
		 * the nmsg payload was never added to an nmsg output, so
		 * deallocate here */
		if (iobuf == NULL && np != NULL)
			nmsg_payload_free(&np);
	}

	/* if we have no iobuf outputs and a stop condition is reached then
	 * we must free the payload here */
	if (iobuf == NULL && np != NULL)
		nmsg_payload_free(&np);

	nmsg_pbmod_fini(iopcap->mod, &clos);
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
