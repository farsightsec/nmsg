/*
 * Copyright (c) 2008, 2009, 2012, 2013 by Internet Systems Consortium, Inc. ("ISC")
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

#include "private.h"

/* Data structures. */

struct nmsg_rate {
	struct timespec next_tick, period, start;
	uint64_t	count;
	unsigned	adj_rate, rate, freq;
};

/* Internal functions. */

static inline int64_t
ts_nanos(struct timespec *ts) {
	return (ts->tv_sec * NMSG_NSEC_PER_SEC + ts->tv_nsec);
}

static inline struct timespec
calc_next_tick(const struct timespec *t, const struct timespec *m) {
	struct timespec res;

	res = *t;
	if (m->tv_sec > 0) {
		res.tv_sec -= (res.tv_sec % m->tv_sec);
		res.tv_sec += m->tv_sec;
	}
	if (m->tv_nsec > 0) {
		res.tv_nsec -= (res.tv_nsec % m->tv_nsec);
		res.tv_nsec += m->tv_nsec;
	} else {
		res.tv_nsec = 0;
	}

	while (res.tv_nsec >= NMSG_NSEC_PER_SEC) {
		res.tv_sec += 1;
		res.tv_nsec -= NMSG_NSEC_PER_SEC;
	}

	return (res);
}

static inline void
adjust_rate(nmsg_rate_t r, struct timespec *now) {
	struct timespec elapsed;
	double ratio;
	unsigned actual_rate;

	/* amount of time elapsed since first call to nmsg_time_sleep() */
	elapsed = *now;
	nmsg_timespec_sub(&r->start, &elapsed);

	/* the average event rate that has been maintained over the
	 * lifespan of this rate-limiter.
	 */
	actual_rate = r->count / (ts_nanos(&elapsed) / (NMSG_NSEC_PER_SEC + 0.0));

	/* simple ratio of nominal event rate and average event rate */
	ratio = r->rate / (actual_rate + 0.0);

	/* clamp this ratio to a small interval */
	if (ratio < 0.99)
		ratio = 0.99;
	if (ratio > 1.01)
		ratio = 1.01;

	/* calculate a new, adjusted rate based on this ratio */
	r->adj_rate *= ratio;

	/* calculate a new tick period based on the adjusted rate */
	const double period = 1.0 / (r->adj_rate + 0.0);
	nmsg_timespec_from_double(period, &r->period);
}

/* Export. */

nmsg_rate_t
nmsg_rate_init(unsigned rate, unsigned freq) {
	struct nmsg_rate *r;

	r = calloc(1, sizeof(*r));
	if (r == NULL)
		return (NULL);
	r->adj_rate = rate;
	r->rate = rate;
	r->freq = freq;

	/* calculate the tick period */
	const double period = 1.0 / (r->rate + 0.0);
	nmsg_timespec_from_double(period, &r->period);

	return (r);
}

void
nmsg_rate_destroy(nmsg_rate_t *r) {
	if (*r != NULL) {
		free(*r);
		*r = NULL;
	}
}

void
nmsg_rate_sleep(nmsg_rate_t r) {
	struct timespec now, til;

	if (r == NULL)
		return;

	/* update the event counter */
	r->count += 1;

	/* fetch the current time */
	clock_gettime(CLOCK_MONOTONIC, &now);

	/* special case: if this is the first call to nmsg_rate_sleep(),
	 * calculate when the next tick will be. this is a little bit more
	 * accurate than calculating it in nmsg_rate_init().
	 */
	if (r->count == 1) {
		r->start = now;
		r->next_tick = calc_next_tick(&now, &r->period);
	}

	/* adjust the rate and period every 'freq' events.
	 * skip the first window of 'freq' events.
	 * disabled if 'freq' is 0.
	 */
	if (r->freq != 0 && (r->count % r->freq) == 0 && r->count > r->freq)
		adjust_rate(r, &now);

	/* 'til', amount of time remaining until the next tick */
	til = r->next_tick;
	nmsg_timespec_sub(&now, &til);

	/* if 'til' is in the past, don't bother sleeping */
	if (ts_nanos(&til) > 0) {
		/* do the sleep */
		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &r->next_tick, NULL);

		/* re-fetch the current time */
		clock_gettime(CLOCK_MONOTONIC, &now);
	}

	/* calculate the next tick */
	r->next_tick = calc_next_tick(&now, &r->period);
}
