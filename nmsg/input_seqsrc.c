/*
 * Copyright (c) 2011 by Internet Systems Consortium, Inc. ("ISC")
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

static void
free_seqsrcs(nmsg_input_t input) {
	struct nmsg_seqsrc *seqsrc, *seqsrc_next;

	seqsrc = ISC_LIST_HEAD(input->stream->seqsrcs);
	while (seqsrc != NULL) {
		if (_nmsg_global_debug >= 5) {
			fprintf(stderr, "%s: source %s/%hu: "
				"count=%" PRIu64 " dropped=%" PRIu64 " (%.4f)\n",
				__func__,
				seqsrc->addr_str, ntohs(seqsrc->key.port),
				seqsrc->count, seqsrc->count_dropped,
				(seqsrc->count_dropped) /
					(seqsrc->count_dropped + seqsrc->count + 1.0)
			);
		}
		input->stream->count_recv += seqsrc->count;
		input->stream->count_drop += seqsrc->count_dropped;
		seqsrc_next = ISC_LIST_NEXT(seqsrc, link);
		free(seqsrc);
		seqsrc = seqsrc_next;
	}

	if (_nmsg_global_debug >= 4 && input->stream->count_recv > 0) {
		double frac = (input->stream->count_drop + 0.0) /
			(input->stream->count_recv + input->stream->count_drop + 0.0);
		fprintf(stderr,
			"%s: input=%p count_recv=%" PRIu64 " count_drop=%" PRIu64 " (%.4f)\n",
			__func__,
			input,
			input->stream->count_recv,
			input->stream->count_drop,
			frac
		);
	}
}

static void
reset_seqsrc(struct nmsg_seqsrc *seqsrc, const char *why) {
	if (_nmsg_global_debug >= 5) {
		fprintf(stderr,
			"%s: resetting source %s/%hu: %s: "
			"count= %" PRIu64 " count_dropped= %" PRIu64 "\n",
			__func__,
			seqsrc->addr_str,
			ntohs(seqsrc->key.port),
			why,
			seqsrc->count,
			seqsrc->count_dropped
		);
	}
	seqsrc->sequence = 0;
	seqsrc->count = 0;
	seqsrc->count_dropped = 0;
}

static void
input_update_seqsrc(nmsg_input_t input, Nmsg__Nmsg *nmsg, struct nmsg_seqsrc *seqsrc) {
	if (!(input->type == nmsg_input_type_stream &&
	      input->stream->type == nmsg_stream_type_sock &&
	      nmsg != NULL &&
	      nmsg->has_sequence &&
	      nmsg->has_sequence_id))
	{
		return;
	}

	if (seqsrc->sequence_id != nmsg->sequence_id) {
		seqsrc->sequence_id = nmsg->sequence_id;
		if (!seqsrc->init) {
			reset_seqsrc(seqsrc, "sequence id mismatch");
			seqsrc->init = true;
		}
	}

	seqsrc->count += 1;

	if (seqsrc->sequence != nmsg->sequence) {
		int64_t delta = ((int64_t)(nmsg->sequence)) -
				((int64_t)(seqsrc->sequence));
		delta %= 4294967296;
		if (delta < 0)
			delta += 4294967296;

		if (seqsrc->init) {
			/* don't count the delta as a drop, since the seqsrc
			 * has just been initialized */
			goto out;
		}

		if (delta > 1048576) {
			/* don't count the delta as a drop, since the delta
			 * is implausibly large */
			reset_seqsrc(seqsrc, "implausibly large delta");
			goto out;
		}

		/* count the delta as a drop */
		seqsrc->count_dropped += delta;

		if (_nmsg_global_debug >= 5) {
			fprintf(stderr,
				"%s: source %s/%hu: expected sequence (%u) != wire sequence (%u), "
				"delta %" PRIu64 ", drop fraction %.4f\n",
				__func__,
				seqsrc->addr_str, ntohs(seqsrc->key.port),
				seqsrc->sequence,
				nmsg->sequence,
				delta,
				(seqsrc->count_dropped) /
					(seqsrc->count_dropped + seqsrc->count + 1.0)
			);
		}
	}
out:
	seqsrc->init = false;
	seqsrc->sequence = nmsg->sequence + 1;
}

static void
get_seqsrc(nmsg_input_t input, struct nmsg_seqsrc **ss, struct sockaddr_storage *addr_ss) {
	struct nmsg_seqsrc *seqsrc, *seqsrc_next;
	struct sockaddr_in *sai;
	struct sockaddr_in6 *sai6;

	seqsrc = ISC_LIST_HEAD(input->stream->seqsrcs);
	while (seqsrc != NULL) {
		seqsrc_next = ISC_LIST_NEXT(seqsrc, link);

		if (addr_ss->ss_family == AF_INET && seqsrc->key.af == AF_INET) {
			sai = (struct sockaddr_in *) addr_ss;
			if (sai->sin_port == seqsrc->key.port &&
			    memcmp(&sai->sin_addr.s_addr, seqsrc->key.ip4, 4) == 0)
			{
				break;
			}
		} else if (addr_ss->ss_family == AF_INET6 && seqsrc->key.af == AF_INET6) {
			sai6 = (struct sockaddr_in6 *) addr_ss;
			if (sai6->sin6_port == seqsrc->key.port &&
			    memcmp(sai6->sin6_addr.s6_addr, seqsrc->key.ip6, 16) == 0)
			{
				break;
			}
		}
		if (seqsrc->last < input->stream->now.tv_sec - NMSG_SEQSRC_GC_INTERVAL) {
			if (_nmsg_global_debug >= 5)
				fprintf(stderr,
					"%s: freeing old source %s/%hu: "
					"count= %" PRIu64 " count_dropped= %" PRIu64 "\n",
					__func__, seqsrc->addr_str, ntohs(seqsrc->key.port),
					seqsrc->count, seqsrc->count_dropped
				);
			ISC_LIST_UNLINK(input->stream->seqsrcs, seqsrc, link);
			input->stream->count_recv += seqsrc->count;
			input->stream->count_drop += seqsrc->count_dropped;
			free(seqsrc);
		}

		seqsrc = seqsrc_next;
	}

	if (seqsrc == NULL) {
		seqsrc = calloc(1, sizeof(*seqsrc));
		assert(seqsrc != NULL);
		seqsrc->init = true;
		seqsrc->last = input->stream->now.tv_sec;

		seqsrc->key.af = addr_ss->ss_family;
		if (seqsrc->key.af == AF_INET) {
			sai = (struct sockaddr_in *) addr_ss;
			seqsrc->key.port = sai->sin_port;
			memcpy(seqsrc->key.ip4, &sai->sin_addr.s_addr, 4);
			inet_ntop(AF_INET,
				  seqsrc->key.ip4, seqsrc->addr_str, sizeof(seqsrc->addr_str));
		} else if (seqsrc->key.af == AF_INET6) {
			sai6 = (struct sockaddr_in6 *) addr_ss;
			seqsrc->key.port = sai6->sin6_port;
			memcpy(seqsrc->key.ip6, sai6->sin6_addr.s6_addr, 16);
			inet_ntop(AF_INET6,
				  seqsrc->key.ip6, seqsrc->addr_str, sizeof(seqsrc->addr_str));
		}

		ISC_LINK_INIT(seqsrc, link);
		ISC_LIST_APPEND(input->stream->seqsrcs, seqsrc, link);
		if (_nmsg_global_debug >= 5)
			fprintf(stderr, "%s: initialized new seqsrc addr= %s port= %hu\n",
				__func__, seqsrc->addr_str, ntohs(seqsrc->key.port));
	} else {
		if (seqsrc != ISC_LIST_HEAD(input->stream->seqsrcs)) {
			ISC_LIST_UNLINK(input->stream->seqsrcs, seqsrc, link);
			ISC_LIST_PREPEND(input->stream->seqsrcs, seqsrc, link);
		}
	}

	*ss = seqsrc;
}
