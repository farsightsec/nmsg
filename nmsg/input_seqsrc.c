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
				seqsrc->addr_str, ntohs(seqsrc->port),
				seqsrc->count, seqsrc->count_dropped,
				(seqsrc->count_dropped) /
					(seqsrc->count_dropped + seqsrc->count + 1.0)
			);
		}
		seqsrc_next = ISC_LIST_NEXT(seqsrc, link);
		free(seqsrc);
		seqsrc = seqsrc_next;
	}
}

static void
input_update_seqsrc(nmsg_input_t input, Nmsg__Nmsg *nmsg, struct nmsg_seqsrc *seqsrc) {
	seqsrc->count += 1;

	if (input->type == nmsg_input_type_stream &&
	    input->stream->type == nmsg_stream_type_sock &&
	    nmsg != NULL && nmsg->has_sequence)
	{
		if (seqsrc->sequence != nmsg->sequence) {
			int64_t delta = ((int64_t)(nmsg->sequence)) -
					((int64_t)(seqsrc->sequence));
			delta %= 4294967296;
			if (delta < 0)
				delta += 4294967296;
			if (seqsrc->init)
				seqsrc->init = false;
			else
				seqsrc->count_dropped += delta;

			if (_nmsg_global_debug >= 5) {
			fprintf(stderr,
				"%s: source %s/%hu: expected sequence (%u) != wire sequence (%u), "
				"delta %" PRIu64 ", drop fraction %.4f\n",
				__func__,
				seqsrc->addr_str, ntohs(seqsrc->port),
				seqsrc->sequence,
				nmsg->sequence,
				delta,
				(seqsrc->count_dropped) /
					(seqsrc->count_dropped + seqsrc->count + 1.0)
			);
			}
		}
		seqsrc->sequence = nmsg->sequence + 1;
	}
}

static void
get_seqsrc(nmsg_input_t input, struct nmsg_seqsrc **ss, struct sockaddr_storage *addr_ss) {
	struct nmsg_seqsrc *seqsrc, *seqsrc_next;
	struct sockaddr_in *sai;
	struct sockaddr_in6 *sai6;

	seqsrc = ISC_LIST_HEAD(input->stream->seqsrcs);
	while (seqsrc != NULL) {
		seqsrc_next = ISC_LIST_NEXT(seqsrc, link);

		if (addr_ss->ss_family == AF_INET && seqsrc->af == AF_INET) {
			sai = (struct sockaddr_in *) addr_ss;
			if (sai->sin_port == seqsrc->port &&
			    memcmp(&sai->sin_addr.s_addr, seqsrc->ip4, 4) == 0)
			{
				break;
			}
		} else if (addr_ss->ss_family == AF_INET6 && seqsrc->af == AF_INET6) {
			sai6 = (struct sockaddr_in6 *) addr_ss;
			if (sai6->sin6_port == seqsrc->port &&
			    memcmp(sai6->sin6_addr.s6_addr, seqsrc->ip6, 16) == 0)
			{
				break;
			}
		}
		if (seqsrc->last < input->stream->now.tv_sec - NMSG_SEQSRC_GC_INTERVAL) {
			if (_nmsg_global_debug >= 5)
				fprintf(stderr,
					"%s: freeing old source %s/%hu: "
					"count= %" PRIu64 " count_dropped= %" PRIu64 "\n",
					__func__, seqsrc->addr_str, ntohs(seqsrc->port),
					seqsrc->count, seqsrc->count_dropped
				);
			ISC_LIST_UNLINK(input->stream->seqsrcs, seqsrc, link);
			free(seqsrc);
		}

		seqsrc = seqsrc_next;
	}

	if (seqsrc == NULL) {
		seqsrc = calloc(1, sizeof(*seqsrc));
		assert(seqsrc != NULL);
		seqsrc->init = true;
		seqsrc->last = input->stream->now.tv_sec;

		seqsrc->af = addr_ss->ss_family;
		if (seqsrc->af == AF_INET) {
			sai = (struct sockaddr_in *) addr_ss;
			seqsrc->port = sai->sin_port;
			memcpy(seqsrc->ip4, &sai->sin_addr.s_addr, 4);
			inet_ntop(AF_INET,
				  seqsrc->ip4, seqsrc->addr_str, sizeof(seqsrc->addr_str));
		} else if (seqsrc->af == AF_INET6) {
			sai6 = (struct sockaddr_in6 *) addr_ss;
			seqsrc->port = sai6->sin6_port;
			memcpy(seqsrc->ip6, sai6->sin6_addr.s6_addr, 16);
			inet_ntop(AF_INET6,
				  seqsrc->ip6, seqsrc->addr_str, sizeof(seqsrc->addr_str));
		}

		ISC_LINK_INIT(seqsrc, link);
		ISC_LIST_APPEND(input->stream->seqsrcs, seqsrc, link);
		if (_nmsg_global_debug >= 5)
			fprintf(stderr, "%s: initialized new seqsrc addr= %s port= %hu\n",
				__func__, seqsrc->addr_str, ntohs(seqsrc->port));
	} else {
		if (seqsrc != ISC_LIST_HEAD(input->stream->seqsrcs)) {
			ISC_LIST_UNLINK(input->stream->seqsrcs, seqsrc, link);
			ISC_LIST_PREPEND(input->stream->seqsrcs, seqsrc, link);
		}
	}

	*ss = seqsrc;
}
