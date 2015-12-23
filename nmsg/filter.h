/*
 * Copyright (c) 2015 by Farsight Security, Inc.
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

#ifndef NMSG_FILTER_H
#define NMSG_FILTER_H

/*! \file nmsg/filter.h
 * \brief Message filtering API.
 */

typedef enum {
	/**
	 * The filter declines to handle this message for an unspecified
	 * reason, and processing should proceed as if the filter did not
	 * exist. If part of a filter chain, filtering should proceed to the
	 * next filter in the chain.
	 */
	nmsg_filter_message_verdict_DECLINED,

	/**
	 * The filter declares that this message should be accepted into the
	 * output stream. If part of a filter chain, remaining filters should
	 * be short-circuited and the message passed into the output stream.
	 */
	nmsg_filter_message_verdict_ACCEPT,

	/**
	 * The filter declares that this message should be dropped from the
	 * output stream. If part of a filter chain, remaining filters should
	 * be short-circuited.
	 */
	nmsg_filter_message_verdict_DROP,
} nmsg_filter_message_verdict;

/**
 * Function pointer type for a function that performs message filtering. The
 * filter function should read the message in 'msg' and return a filter verdict
 * in the 'vres' parameter-return variable.
 *
 * The filter function may alter the message object, or it may replace the
 * message object entirely with a new message. If the filter function replaces
 * the message object, it is responsible for disposing of the old message, for
 * instance by calling nmsg_message_destroy().
 *
 * \param[in,out] msg Pointer to message object.
 * \param[in] user NULL or a filter-specific user pointer.
 * \param[out] vres The filter verdict.
 *
 * \return #nmsg_res_success if a filter verdict was successfully determined,
 * or any non-success result code otherwise. A non-success result code
 * indicates to the caller that a fatal error has occurred and that processing
 * should immediately stop.
 */
typedef nmsg_res (*nmsg_filter_message_fp)(nmsg_message_t *msg,
					   void *user,
					   nmsg_filter_message_verdict *vres);

#endif /* NMSG_FILTER_H */
