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

#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#include "nmsg.h"
#include "nmsg_private.h"

nmsg_rate 
nmsg_rate_init(int call_rate) {
	struct nmsg_rate *r;

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (NULL);
	r->call_rate = call_rate;
	r->gtod_rate = call_rate / 10;
	r->sleep_rate = call_rate / 100;
	r->ts.tv_sec = 0;
	r->ts.tv_nsec = 4E6;

	if(r->gtod_rate == 0)
		r->gtod_rate = 1;
	if(r->sleep_rate == 0)
		r->sleep_rate = 1;

	gettimeofday(&r->tv[0], NULL);
	return r;
}

void
nmsg_rate_destroy(nmsg_rate *r) {
	free(*r);
	*r = NULL;
}

void
nmsg_rate_sleep(nmsg_rate r) {
	int d;
	double d0, d1;

	(r->call_no)++;
	(r->call_no_last)++;
	if (r->call_no % r->sleep_rate == 0)
		nanosleep(&r->ts, NULL);
	if (r->call_no % r->gtod_rate == 0) {
		gettimeofday(&r->tv[1], NULL);
		d0 = r->tv[0].tv_sec + r->tv[0].tv_usec / 1E6;
		d1 = r->tv[1].tv_sec + r->tv[1].tv_usec / 1E6;
		r->cur_rate = ((int) (r->call_no_last / (d1 - d0)));
		if (abs(r->cur_rate - r->call_rate) > 10) {
			if (r->cur_rate - r->call_rate > 0) {
				if (r->sleep_rate > 1) {
					d = r->sleep_rate / 10;
					r->sleep_rate -= (d > 1 ? d : 1);
				}
			} else if (r->sleep_rate < 1E6) {
				d = r->sleep_rate / 10;
				r->sleep_rate += (d > 1 ? d : 1);
			}
		}
		r->call_no_last = 0;
		r->tv[0] = r->tv[1];
	}
}
