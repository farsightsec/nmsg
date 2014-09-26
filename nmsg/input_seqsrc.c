/*
 * Copyright (c) 2011-2013 by Farsight Security, Inc.
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

/* Macros. */

#define IDFMT "%016" PRIx64

/* Forward. */

static void	reset_seqsrc(struct nmsg_seqsrc *, const char *);

/* Internal functions. */

void
_input_seqsrc_destroy(nmsg_input_t input) {
	struct nmsg_seqsrc *seqsrc, *seqsrc_next;

	seqsrc = ISC_LIST_HEAD(input->stream->seqsrcs);
	while (seqsrc != NULL) {
		_nmsg_dprintf(5, "%s: source id= " IDFMT ": "
			      "count=%" PRIu64 " dropped=%" PRIu64 " (%.4f)\n",
			      __func__,
			      seqsrc->key.sequence_id,
			      seqsrc->count, seqsrc->count_dropped,
			      (seqsrc->count_dropped) /
				(seqsrc->count_dropped + seqsrc->count + 1.0)
		);
		seqsrc_next = ISC_LIST_NEXT(seqsrc, link);
		free(seqsrc);
		seqsrc = seqsrc_next;
	}

	if (_nmsg_global_debug >= 4 && input->stream->count_recv > 0) {
		double frac = (input->stream->count_drop + 0.0) /
			(input->stream->count_recv + input->stream->count_drop + 0.0);
		_nmsg_dprintf(4,
			"%s: input=%p count_recv=%" PRIu64 " count_drop=%" PRIu64 " (%.4f)\n",
			__func__,
			input,
			input->stream->count_recv,
			input->stream->count_drop,
			frac
		);
	}
}

size_t
_input_seqsrc_update(nmsg_input_t input, struct nmsg_seqsrc *seqsrc, Nmsg__Nmsg *nmsg) {
	size_t drop = 0;

	if (!(input->type == nmsg_input_type_stream &&
	      nmsg != NULL &&
	      nmsg->has_sequence &&
	      nmsg->has_sequence_id))
	{
		return (drop);
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
		drop = delta;
		seqsrc->count_dropped += delta;

		_nmsg_dprintf(5,
			      "%s: source id= " IDFMT ": expected sequence (%u) != "
			      "wire sequence (%u), delta %" PRIu64 ", drop fraction %.4f\n",
			      __func__,
			      seqsrc->key.sequence_id,
			      seqsrc->sequence,
			      nmsg->sequence,
			      delta,
			      (seqsrc->count_dropped) /
				(seqsrc->count_dropped + seqsrc->count + 1.0)
		);
	}
out:
	seqsrc->init = false;
	seqsrc->sequence = nmsg->sequence + 1;
	return (drop);
}

struct nmsg_seqsrc *
_input_seqsrc_get(nmsg_input_t input, Nmsg__Nmsg *nmsg) {
	struct nmsg_seqsrc *seqsrc, *seqsrc_next;
	struct sockaddr_in *sai;
	struct sockaddr_in6 *sai6;
	struct sockaddr_storage *addr_ss = &input->stream->addr_ss;

	seqsrc = ISC_LIST_HEAD(input->stream->seqsrcs);
	while (seqsrc != NULL) {
		seqsrc_next = ISC_LIST_NEXT(seqsrc, link);

		if (nmsg->sequence_id == seqsrc->key.sequence_id &&
		    addr_ss->ss_family == AF_INET &&
		    seqsrc->key.af == AF_INET)
		{
			sai = (struct sockaddr_in *) addr_ss;
			if (sai->sin_port == seqsrc->key.port &&
			    memcmp(&sai->sin_addr.s_addr, seqsrc->key.ip4, 4) == 0)
			{
				break;
			}
		} else if (nmsg->sequence_id == seqsrc->key.sequence_id &&
			   addr_ss->ss_family == AF_INET6 &&
			   seqsrc->key.af == AF_INET6)
		{
			sai6 = (struct sockaddr_in6 *) addr_ss;
			if (sai6->sin6_port == seqsrc->key.port &&
			    memcmp(sai6->sin6_addr.s6_addr, seqsrc->key.ip6, 16) == 0)
			{
				break;
			}
		} else if (nmsg->sequence_id == seqsrc->key.sequence_id &&
			   seqsrc->key.af == AF_UNSPEC)
		{
			break;
		}

		if (seqsrc->last < input->stream->now.tv_sec - NMSG_SEQSRC_GC_INTERVAL) {
			_nmsg_dprintf(6,
				      "%s: freeing old source id= " IDFMT ": "
				      "count= %" PRIu64 " count_dropped= %" PRIu64 "\n",
				      __func__, seqsrc->key.sequence_id,
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

		if (input->stream->type == nmsg_stream_type_sock) {
			seqsrc->key.sequence_id = nmsg->sequence_id;
			seqsrc->key.af = addr_ss->ss_family;
			if (seqsrc->key.af == AF_INET) {
				sai = (struct sockaddr_in *) addr_ss;
				seqsrc->key.port = sai->sin_port;
				memcpy(seqsrc->key.ip4, &sai->sin_addr.s_addr, 4);
				inet_ntop(AF_INET,
					  seqsrc->key.ip4,
					  seqsrc->addr_str,
					  sizeof(seqsrc->addr_str));
			} else if (seqsrc->key.af == AF_INET6) {
				sai6 = (struct sockaddr_in6 *) addr_ss;
				seqsrc->key.port = sai6->sin6_port;
				memcpy(seqsrc->key.ip6, sai6->sin6_addr.s6_addr, 16);
				inet_ntop(AF_INET6,
					  seqsrc->key.ip6,
					  seqsrc->addr_str,
					  sizeof(seqsrc->addr_str));
			}
#ifdef HAVE_LIBXS
		} else if (input->stream->type == nmsg_stream_type_xs) {
			seqsrc->key.sequence_id = nmsg->sequence_id;
			seqsrc->key.af = AF_UNSPEC;
		}
#else /* HAVE_LIBXS */
		}
#endif /* HAVE_LIBXS */

		ISC_LINK_INIT(seqsrc, link);
		ISC_LIST_APPEND(input->stream->seqsrcs, seqsrc, link);
		_nmsg_dprintf(6, "%s: initialized new seqsrc id= " IDFMT "\n",
			      __func__, seqsrc->key.sequence_id);
	} else {
		if (seqsrc != ISC_LIST_HEAD(input->stream->seqsrcs)) {
			ISC_LIST_UNLINK(input->stream->seqsrcs, seqsrc, link);
			ISC_LIST_PREPEND(input->stream->seqsrcs, seqsrc, link);
		}
	}

	seqsrc->last = input->stream->now.tv_sec;
	return (seqsrc);
}

/* Private functions. */

static void
reset_seqsrc(struct nmsg_seqsrc *seqsrc, const char *why) {
	_nmsg_dprintf(6,
		      "%s: resetting source id= " IDFMT ": %s: "
		      "count= %" PRIu64 " count_dropped= %" PRIu64 "\n",
		      __func__,
		      seqsrc->key.sequence_id,
		      why,
		      seqsrc->count,
		      seqsrc->count_dropped
	);
	seqsrc->sequence = 0;
	seqsrc->count = 0;
	seqsrc->count_dropped = 0;
}
