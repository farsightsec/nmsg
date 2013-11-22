/*
 * Copyright (c) 2012 by Farsight Security, Inc.
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

#define QUANTUM		0.1

/* Data structures. */

struct nmsg_brate {
	size_t		qu;
	size_t		target_byte_rate;
	double		t_time;
	struct timespec	container_zero_time;
	struct timespec	container_last_time;
};

/* Export. */

struct nmsg_brate *
_nmsg_brate_init(size_t target_byte_rate) {
	struct nmsg_brate *b;

	b = calloc(1, sizeof(*b));
	if (b == NULL)
		return (NULL);
	b->target_byte_rate = target_byte_rate;
	nmsg_timespec_get(&b->container_last_time);

	return (b);
}

void
_nmsg_brate_destroy(struct nmsg_brate **b) {
	if (*b != NULL) {
		free(*b);
		*b = NULL;
	}
}

void
_nmsg_brate_sleep(struct nmsg_brate *b,
		  size_t container_sz,
		  size_t n_payloads,
		  size_t n)
{
	struct timespec now;

	/* get current time */
	nmsg_timespec_get(&now);

	if (n == 0) {
		/* new container */
		double c_time;
		struct timespec container_time = now;

		/* calculate c_time, the overhead taken by the deserialization
		 * of the container. if this is the very first container
		 * processed since _nmsg_brate_init() was called, this value
		 * will also include some additional startup overhead.
		 */
		nmsg_timespec_sub(&b->container_last_time, &container_time);
		c_time = nmsg_timespec_to_double(&container_time);

		/* calculate t_time, the theoretical amount of time that should
		 * be spent on this container to maintain the target byte rate.
		 * since container sizes can vary especially if this is the last
		 * container in a file, this is a per-container value.
		 */
		b->t_time = (container_sz + 0.0) / (b->target_byte_rate);

		/* since c_time was already consumed in overhead, subtract it
		 * from t_time, if it is smaller.
		 */
		if (c_time < b->t_time)
			b->t_time -= c_time;

		/* calculate qu, the payload quantum. */
		b->qu = QUANTUM * n_payloads;
		if (b->qu < 1)
			b->qu = 1;

		/* store the container zero time, which will be used to
		 * calculate the elapsed time every qu payloads.
		 */
		b->container_zero_time = now;
	} else if ((n % b->qu) == 0 || n == n_payloads - 1) {
		double frac;
		double e_time;
		double s_time;
		double t_time_frac;
		struct timespec ts;

		/* calculate frac, the fraction of the container that has been
		 * processed so far. note that this is only an estimate, since
		 * it is assumed that payloads are of average size, on average.
		 */
		frac = (n + 0.0) / n_payloads;

		/* calculate e_time, the time elapsed from the start of this
		 * container to the current payload.
		 */
		ts = now;
		nmsg_timespec_sub(&b->container_zero_time, &ts);
		e_time = nmsg_timespec_to_double(&ts);

		/* calculate t_time_frac, the part of t_time that should be
		 * consumed in order to maintain the target byte rate.
		 */
		t_time_frac = frac * b->t_time;

		/* calculate s_time, the amount of time to sleep (if positive),
		 * in order to maintain the target byte rate, by subtracting the
		 * elapsed time since the start of the container from
		 * t_time_frac.
		 */
		s_time = t_time_frac - e_time;

		/* do the actual sleep, if possible. */
		if (s_time > 0.0) {
			nmsg_timespec_from_double(s_time, &ts);
			nmsg_timespec_sleep(&ts);
		}

		if (n == n_payloads - 1) {
			/* this is the last payload of the container. save the
			 * current time so that the overhead taken by
			 * deserialization of the next container can be
			 * accounted for.
			 */
			nmsg_timespec_get(&b->container_last_time);
		}
	}
}
