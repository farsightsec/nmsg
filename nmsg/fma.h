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

#ifndef NMSG_FMA_H
#define NMSG_FMA_H

/*****
 ***** Module Info
 *****/

/*! \file nmsg/fma.h
 * \brief FIFO-optimized memory allocator.
 *
 * \li MP:
 *	Clients must ensure synchronized access to an nmsg_fma object, or
 *	instantiate an nmsg_fma object for each thread.
 *
 * \li Reliability:
 *	nmsg_fma allocated memory must be freed in the same order as
 *	allocation.
 */

/***
 *** Imports
 ***/

#include <sys/types.h>

#include <nmsg.h>

/***
 *** Functions
 ***/

nmsg_fma_t
nmsg_fma_init(const char *name, size_t mb, unsigned debug);
/*%<
 * Initialize a new nmsg_fma allocator.
 *
 * Requires:
 *
 * \li	'name' is a string identifying the pool of memory allocated by this
 *	nmsg_fma instance.
 *
 * \li	'mb' is the number of megabytes requested at a time from the
 *	underlying operating system. Individual allocations cannot exceed
 *	this size.
 *
 * \li	'debug' is the debugging level. Values larger than zero will cause
 *	information useful for debugging allocations to be logged.
 *
 * Returns:
 *
 * \li	An opaque pointer that is NULL on failure or non-NULL on success.
 */

void
nmsg_fma_destroy(nmsg_fma_t *fma);
/*%<
 * Destroy resources allocated for an nmsg_fma allocator.
 *
 * Requires:
 *
 * \li	'*fma' is a valid pointer to an nmsg_fma object.
 *
 * Ensures:
 *
 * \li	'fma' will be NULL on return, and all memory blocks associated with
 *	the allocator will be returned to the operating system.
 */

void *
nmsg_fma_alloc(nmsg_fma_t fma, size_t sz);
/*%<
 * Allocate a block of memory.
 *
 * Requires:
 *
 * \li	'fma' is a valid nmsg_fma object.
 *
 * \li	'sz' is between 0 and the block size of the allocator.
 *
 * Returns:
 *
 * \li	A void pointer that is NULL on failure or non-NULL on success.
 */

void
nmsg_fma_free(nmsg_fma_t fma, void *ptr);
/*%<
 * Free a block of memory.
 *
 * Requires:
 *
 * \li	'fma' is a valid nmsg_fma object.
 *
 * \li	'*ptr' is a pointer to a block of memory allocated by
 *	nmsg_fma_alloc().
 *
 * Ensures:
 *
 * \li	When the number of allocations for an nmsg_fma memory block reaches
 *	zero, the block will be returned to the operating system.
 */

#endif /* NMSG_FMA_H */
