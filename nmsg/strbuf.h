/*
 * Copyright (c) 2009-2015 by Farsight Security, Inc.
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

#ifndef NMSG_STRBUF_H
#define NMSG_STRBUF_H

/*! \file nmsg/strbuf.h
 * \brief String buffers
 *
 * Dynamically sized strings that may be appended to or reset.
 */

/** String buffer. */
struct nmsg_strbuf {
	char	*pos;	/*%< end of string */
	char	*data;	/*%< buffer for string data */
	size_t	bufsz;	/*%< size of data allocation */
};

/**
 * Initialize a string buffer.
 *
 * \return Initialized string buffer, or NULL on memory allocation failure.
 */
struct nmsg_strbuf *nmsg_strbuf_init(void);

/**
 * Destroy all resources associated with a string buffer.
 *
 * \param[in] sb pointer to string buffer.
 */
void nmsg_strbuf_destroy(struct nmsg_strbuf **sb);

/**
 * Append to a string buffer.
 *
 * \param[in] sb string buffer.
 *
 * \param[in] fmt format string to be passed to vsnprintf.
 *
 * \param[in] ... arguments to vsnprintf.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 * \return #nmsg_res_failure
 */
nmsg_res nmsg_strbuf_append(struct nmsg_strbuf *sb, const char *fmt, ...);

/**
 * Reset a string buffer.
 *
 * Resets the size of the internal buffer to the default size, but does not
 * clear the contents of the buffer.
 *
 * \param[in] sb string buffer.
 *
 * \return #nmsg_res_success
 * \return #nmsg_res_memfail
 */
nmsg_res nmsg_strbuf_reset(struct nmsg_strbuf *sb);

/**
 * Find the length of the used portion of the string buffer.
 *
 * \param[in] sb string buffer.
 *
 * \return Number of bytes consumed by the string.
 */
size_t nmsg_strbuf_len(struct nmsg_strbuf *sb);

#endif /* NMSG_STRBUF_H */
