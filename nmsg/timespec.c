/*
 * Copyright (c) 2008, 2009, 2011, 2012 by Internet Systems Consortium, Inc. ("ISC")
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
