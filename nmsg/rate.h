/*
 * Copyright (c) 2008-2015 by Farsight Security, Inc.
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

#ifndef NMSG_RATE_H
#define NMSG_RATE_H

/*! \file nmsg/rate.h
 * \brief Rate-limiting.
 *
 * Tight loops can be slowed down by repeated calls to nmsg_rate_sleep(). This
 * works best when the amount of time elapsed between successive calls is
 * approximately the same.
 *
 * <b>Reliability:</b>
 *	\li Rate-limiting is accurate to within about 1-10% of the target rate
 *	limit, provided that the scheduling frequency is smaller than the rate
 *	limit.
 */

/**
 * Initialize a new nmsg_rate_t object.
 *
 * 'freq' should usually be about 1-10% of 'rate'.
 *
 * \param[in] rate target rate limit in Hz, greater than 0.
 *
 * \param[in] freq how often the rate limit will be checked, i.e., every 'freq'
 *	calls to nmsg_rate_sleep(), greater than 0.
 */
nmsg_rate_t
nmsg_rate_init(unsigned rate, unsigned freq);

/**
 * Destroy an nmsg_rate_t object.
 *
 * \param[in] r pointer to an nmsg_rate_t object.
 */
void
nmsg_rate_destroy(nmsg_rate_t *r);

/**
 * Sleep if necessary to maintain the target rate limit.
 *
 * \param[in] r nmsg_rate_t object.
 */
void
nmsg_rate_sleep(nmsg_rate_t r);

#endif /* NMSG_RATE_H */
