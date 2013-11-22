/*
 * Copyright (c) 2008, 2011, 2012 by Farsight Security, Inc.
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
 * Add timespecs a and b, placing result in b.  (b = b + a).
 *
 * \param[in] a
 * \param[in,out] b
 */
void
nmsg_timespec_add(const struct timespec *a, struct timespec *b);

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

/**
 * Convert floating point number of seconds to timespec.
 *
 * \param[in] seconds Floating point number of seconds.
 * \param[out] ts
 */
void
nmsg_timespec_from_double(double seconds, struct timespec *ts);

#endif /* NMSG_TIMESPEC_H */
