/*
 * Copyright (c) 2008, 2009, 2012, 2013 by Farsight Security, Inc.
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

	/* what clock to use depends on whether clock_nanosleep() is available */
#if HAVE_CLOCK_NANOSLEEP
	static const clockid_t NMSG_RATE_CLOCK = CLOCK_MONOTONIC;
#else
	static const clockid_t NMSG_RATE_CLOCK = CLOCK_REALTIME;
#endif

	if (r == NULL)
		return;

	/* update the event counter */
	r->count += 1;

	/* fetch the current time */
	clock_gettime(NMSG_RATE_CLOCK, &now);

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
#if HAVE_CLOCK_NANOSLEEP
		clock_nanosleep(NMSG_RATE_CLOCK, TIMER_ABSTIME, &r->next_tick, NULL);
#else
		struct timespec rel;
		rel = r->next_tick;
		nmsg_timespec_sub(&now, &rel);
		nmsg_timespec_sleep(&rel);
#endif

		/* re-fetch the current time */
		clock_gettime(NMSG_RATE_CLOCK, &now);
	}

	/* calculate the next tick */
	r->next_tick = calc_next_tick(&now, &r->period);
}
