/* nmsg_rate - rate limiting interface */

/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#include <stdlib.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>

#include "nmsg.h"
#include "nmsg_private.h"

/* From FreeBSD sys/time.h "timespecsub" */
#define TS_SUBTRACT(vvp, uvp)                                           \
	do {                                                            \
		(vvp)->tv_sec -= (uvp)->tv_sec;                         \
		(vvp)->tv_nsec -= (uvp)->tv_nsec;                       \
		if ((vvp)->tv_nsec < 0) {                               \
			(vvp)->tv_sec--;                                \
			(vvp)->tv_nsec += 1000000000;                   \
		}                                                       \
	} while (0)

/* Data structures. */

struct nmsg_rate {
	unsigned	count, limit, rate;
	struct timespec	start, ipg;
};

/* Export. */

nmsg_rate 
nmsg_rate_init(unsigned rate, unsigned freq) {
	struct nmsg_rate *r;

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (NULL);

	nmsg_time_get(&r->start);
	r->ipg.tv_nsec = 1E9 / freq;
	r->rate = rate;
	r->limit = ((rate / freq) * 100) / 90;
	return (r);
}

void
nmsg_rate_destroy(nmsg_rate *r) {
	free(*r);
	*r = NULL;
}

void
nmsg_rate_sleep(nmsg_rate r) {
	if (r->limit != 0) {
		if (++(r->count) >= r->limit) {
			struct timespec ival, now;

			nmsg_time_sleep(&r->ipg);
			nmsg_time_get(&now);
			ival = now;
			TS_SUBTRACT(&ival, &r->start);
			if (ival.tv_sec == 0) {
				unsigned qrate = (r->count * 1E6) /
						 (ival.tv_nsec / 1E3);

				r->limit *= r->rate;
				if (qrate != 0)
					r->limit /= qrate;

			}
			r->start = now;
			r->count = 1;
		}
	}
}
