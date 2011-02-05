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

#ifndef NMSG_TIMESPEC_H
#define NMSG_TIMESPEC_H

/*! \file nmsg/timespec.h
 * \brief Sleeping and getting the current time.
 */

#include <time.h>

/**
 * Get the current time.
 *
 * If available, clock_gettime() will be used to attempt to get the current
 * real time. If unavailable, gettimeofday() will be used and scaled up to
 * nanosecond precision.
 *
 * \param[out] ts current time.
 */
void
nmsg_timespec_get(struct timespec *ts);

/**
 * Sleep.
 *
 * nanosleep() will be called, and reinvoked if interrupted.
 *
 * \param[in] ts duration to sleep.
 */
void
nmsg_timespec_sleep(const struct timespec *ts);

/**
 * Subtract timespec b from a, placing result in b.  (b = b - a).
 *
 * \param[in] a
 * \param[in,out] b
 */
void
nmsg_timespec_sub(const struct timespec *a, struct timespec *b);

/**
 * Convert timespec to floating point representation.
 *
 * \param[in] ts
 *
 * \return Floating point number of seconds.
 */
double
nmsg_timespec_to_double(const struct timespec *ts);

#endif /* NMSG_TIMESPEC_H */
