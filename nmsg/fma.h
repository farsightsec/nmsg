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

/*! \file nmsg/fma.h
 * \brief FIFO-optimized memory allocator.
 *
 * This is a very low overhead allocator designed for situations where
 * allocations will always be freed in FIFO order.
 *
 * The memory allocated by nmsg_fma is unaligned.
 *
 * <b>MP:</b>
 *	\li Clients must ensure synchronized access to an nmsg_fma_t object, or
 *	instantiate an nmsg_fma_t object for each thread.
 *
 * <b>Reliability:</b>
 *	\li nmsg_fma allocated memory <b>must</b> be freed in the same order as
 *	allocation.
 */

#include <sys/types.h>

#include <nmsg.h>

/**
 * Initialize a new nmsg_fma allocator.
 *
 * \param[in] name string identifying the pool of memory allocated by this
 *	nmsg_fma_t instance.
 *
 * \param[in] mb number of megabytes requested at a time from the underlying
 *	operating system. Individual allocations cannot exceed this size.
 *
 * \param[in] debug debugging level. Values larger than zero will cause
 *	information useful for allocation debugging to be logged to stderr.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_fma_t
nmsg_fma_init(const char *name, size_t mb, unsigned debug);

/**
 * Destroy resources allocated for an nmsg_fma allocator.
 *
 * \param[in] f pointer to a valid nmsg_fma_t object. It will be NULL on return,
 *	and all memory blocks associated with the allocator will be returned to
 *	the operating system.
 */
void
nmsg_fma_destroy(nmsg_fma_t *f);

/**
 * Allocate a block of memory.
 *
 * \param[in] f valid nmsg_fma object.
 *
 * \param[in] sz between 0 and the block size of the allocator.
 *
 * \return Void pointer that is NULL on failure or non-NULL on success.
 */
void *
nmsg_fma_alloc(nmsg_fma_t f, size_t sz);

/**
 * Free a block of memory allocated by the nmsg_fma allocator.
 *
 * When the number of allocations for an nmsg_fma memory block reaches zero,
 * the block will be returned to the operating system.
 *
 * \param[in] f valid nmsg_fma_t object.
 *
 * \param[in] ptr pointer to a block of memory allocated by nmsg_fma_alloc().
 */
void
nmsg_fma_free(nmsg_fma_t f, void *ptr);

#endif /* NMSG_FMA_H */
