/*
 * Copyright (c) 2008, 2009, 2011-2013 by Farsight Security, Inc.
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

/* Export. */

void
nmsg_timespec_get(struct timespec *now) {
#ifdef HAVE_CLOCK_GETTIME
	(void) clock_gettime(CLOCK_REALTIME, now);
#else
	struct timeval tv;
	(void) gettimeofday(&tv, NULL);
	now->tv_sec = tv.tv_sec;
	now->tv_nsec = tv.tv_usec * 1000;
#endif
}

void
nmsg_timespec_sleep(const struct timespec *ts) {
	struct timespec rqt, rmt;

	for (rqt = *ts; nanosleep(&rqt, &rmt) < 0 && errno == EINTR; rqt = rmt)
		;
}

void
nmsg_timespec_add(const struct timespec *a, struct timespec *b) {
	b->tv_sec += a->tv_sec;
	b->tv_nsec += a->tv_nsec;
	while (b->tv_nsec >= NMSG_NSEC_PER_SEC) {
		b->tv_sec += 1;
		b->tv_nsec -= NMSG_NSEC_PER_SEC;
	}
}

void
nmsg_timespec_sub(const struct timespec *a, struct timespec *b) {
	b->tv_sec -= a->tv_sec;
	b->tv_nsec -= a->tv_nsec;
	if (b->tv_nsec < 0) {
		b->tv_sec -= 1;
		b->tv_nsec += NMSG_NSEC_PER_SEC;
	}
}

double
nmsg_timespec_to_double(const struct timespec *ts) {
	return (ts->tv_sec + ts->tv_nsec / 1E9);
}

void
nmsg_timespec_from_double(double seconds, struct timespec *ts) {
	ts->tv_sec = (time_t) seconds;
	ts->tv_nsec = (long) ((seconds - ((int) seconds)) * 1E9);
}
