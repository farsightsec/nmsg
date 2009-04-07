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

#ifndef NMSG_RATE_H
#define NMSG_RATE_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/rate.h
 * \brief Rate-limiting.
 *
 * \li Reliability:
 *	Rate-limiting is accurate to within about 1-10% of the target rate
 *	limit, provided that the scheduling frequency is smaller than the
 *	rate limit.
 */

/***
 *** Imports
 ***/

#include <nmsg.h>

/***
 *** Functions
 ***/

nmsg_rate
nmsg_rate_init(unsigned rate, unsigned freq);
/*%<
 * Initialize a new nmsg_rate object.
 *
 * Requires:
 *
 * \li	'rate' >= 0, in Hz, is the target rate limit.
 *
 * \li	'freq' >= 0 specifies how often the rate limit will be checked,
 *	i.e., every 'freq' calls to nmsg_rate_sleep().
 *
 * Notes:
 *	'freq' should usually be about 10% of 'rate'.
 */

void
nmsg_rate_destroy(nmsg_rate *r);
/*%<
 * Destroy an nmsg_rate object.
 *
 * Requires:
 *
 * \li	'*r' is a valid pointer to an nmsg_rate object.
 *
 * Ensures:
 *
 * \li	'r' will be NULL on return.
 */

void
nmsg_rate_sleep(nmsg_rate r);
/*%<
 * Sleep if necessary to maintain the target rate limit.
 *
 * Requires:
 *
 * \li	'r' is a valid nmsg_rate object.
 */

#endif /* NMSG_RATE_H */
