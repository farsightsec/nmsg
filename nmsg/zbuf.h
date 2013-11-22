/*
 * Copyright (c) 2009 by Farsight Security, Inc.
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

#ifndef NMSG_ZBUF_H
#define NMSG_ZBUF_H

/*! \file nmsg/zbuf.h
 * \brief Compressed buffers.
 */

#include <nmsg.h>

/**
 * Initialize an nmsg_zbuf_t object for deflation.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_zbuf_t
nmsg_zbuf_deflate_init(void);

/**
 * Initialize an nmsg_zbuf_t object for inflation.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_zbuf_t
nmsg_zbuf_inflate_init(void);

/**
 * Destroy all resources associated with an nmsg_zbuf_t object.
 *
 * \param[in] zb pointer to nmsg_zbuf_t object.
 */
void
nmsg_zbuf_destroy(nmsg_zbuf_t *zb);

/**
 * Deflate a buffer.
 *
 * \param[in] zb nmsg_zbuf_t object initialized for deflation.
 *
 * \param[in] len length of buffer to compress.
 *
 * \param[in] buf buffer to compress.
 *
 * \param[out] z_len length of compressed buffer.
 *
 * \param[out] z_buf compressed buffer. Allocated by the caller and should be at
 *	least as large as 'buf'.
 *
 * \return #nmsg_res_success
 */
nmsg_res
nmsg_zbuf_deflate(nmsg_zbuf_t zb, size_t len, u_char *buf,
		  size_t *z_len, u_char *z_buf);

/**
 * Inflate a buffer.
 *
 * \param[in] zb nmsg_zbuf_t object initialized for inflation.
 *
 * \param[in] z_len length of compressed buffer.
 *
 * \param[in] z_buf compressed buffer.
 *
 * \param[out] u_len length of uncompressed buffer.
 *
 * \param[out] u_buf pointer to uncompressed buffer. Should be freed by the
 *	caller with free().
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 * \return #nmsg_res_failure
 */
nmsg_res
nmsg_zbuf_inflate(nmsg_zbuf_t zb, size_t z_len, u_char *z_buf,
		  size_t *u_len, u_char **u_buf);

#endif /* NMSG_ZBUF_H */
