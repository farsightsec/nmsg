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

#include <sys/time.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nmsg.h"

/* Data structures. */

struct nmsg_rate {
	double		start;
	uint64_t	count;
	unsigned	rate, freq;
};

/* Export. */

nmsg_rate 
nmsg_rate_init(unsigned rate, unsigned freq) {
	struct nmsg_rate *r;
	struct timespec ts;

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (NULL);

	nmsg_timespec_get(&ts);
	r->start = ts.tv_sec + ts.tv_nsec / 1E9;
	r->rate = rate;
	r->freq = freq;
	return (r);
}

void
nmsg_rate_destroy(nmsg_rate *r) {
	free(*r);
	*r = NULL;
}

void
nmsg_rate_sleep(nmsg_rate r) {
	r->count += 1;
	if (r->count % r->freq == 0) {
		struct timespec ts;
		double d, cur_rate, over;

		nmsg_timespec_get(&ts);
		d = (ts.tv_sec + ts.tv_nsec / 1E9) - r->start;
		cur_rate = r->count / d;
		over = cur_rate - r->rate;

		if (over > 0.0) {
			double sleep;

			sleep = over / cur_rate;
			ts.tv_sec = floor(sleep);
			ts.tv_nsec = (sleep - ts.tv_sec) * 1E9;
			nmsg_timespec_sleep(&ts);
		}
	}
}
