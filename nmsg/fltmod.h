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

#ifndef NMSG_FLTMOD_H
#define NMSG_FLTMOD_H

/*! \file nmsg/fltmod.h
 * \brief Loading and calling external message filter modules.
 *
 * This file defines the interface for loading and calling filter modules. For
 * the interface that developers of message filter modules must implement, see
 * nmsg/fltmod_plugin.h.
 *
 * Message filter modules allow a message filtering function to be implemented
 * externally in a dynamically loaded plugin.
 *
 * A filter module must first be loaded with nmsg_fltmod_init(). If this
 * succeeds, nmsg_fltmod_thread_init() must be called by each thread that wants
 * to perform filtering with this module, even if the caller is
 * single-threaded. The 'thr_data' value returned by nmsg_fltmod_thread_init()
 * must be provided as the 'thr_data' parameter to nmsg_fltmod_filter_message().
 *
 * Filter functions may alter or replace the message object.
 *
 * Each thread that calls nmsg_fltmod_thread_init() must clean up by calling
 * nmsg_fltmod_thread_fini(), and after each thread has cleaned up, the module
 * itself may be cleaned up by calling nmsg_fltmod_destroy().
 */

#include <nmsg/filter.h>

/**
 * Initialize a filter module with the given parameters. Calls the module's
 * 'module_init' function.
 *
 * \param name
 *	The name of the filter module, which is used to construct the filesystem
 *	path to the shared object containing the filter module. This may either
 *	be a real, complete filesystem path (absolute or relative) that begins
 *	with "/" or "./", or it may be a short "convenience" name that will be
 *	expanded to a real filesystem path. For example, the short name "sample"
 *	might be expanded to a long name like
 *	"/usr/lib/nmsg/nmsg_flt1_sample.so".
 *
 * \param param
 *	Pointer to a value that will be passed to the 'module_init' function.
 *	Specifies module-specific configuration.
 *
 * \param len_param
 *	Length of the 'param' value. Passed to the 'module_init' function.
 *
 * \return Opaque pointer that is NULL on failure or non-NULL on success.
 */
nmsg_fltmod_t
nmsg_fltmod_init(const char *name, const void *param, const size_t len_param);

/**
 * Destroy a filter module. Calls the module's 'module_fini' function. All
 * calls to nmsg_fltmod_thread_fini() must complete before calling this
 * function.
 *
 * \param[in] fltmod
 *	Initialized fltmod.
 */
void
nmsg_fltmod_destroy(nmsg_fltmod_t *fltmod);

/**
 * Initialize thread-specific data for the filter module. Must be called by a
 * processing thread before calling nmsg_fltmod_filter_message(). Calls the
 * module's 'thread_init' function.
 *
 * Each thread that calls nmsg_fltmod_thread_init() must perform a
 * corresponding call to nmsg_fltmod_thread_fini() before nmsg_fltmod_destroy()
 * can be called.
 *
 * \param fltmod
 *	Initialized fltmod.
 *
 * \param[out] thr_data
 *	Opaque data pointer specific to the calling thread. This pointer must be
 *	supplied in subsequent calls to nmsg_fltmod_filter_message() or
 *	nmsg_fltmod_thread_fini().
 *
 * \return #nmsg_res_success
 *	If the thread data was successfully initialized.
 * \return
 *	Any other result may be returned by the module's 'thread_init' function
 *	to indicate an error.
 */
nmsg_res
nmsg_fltmod_thread_init(nmsg_fltmod_t fltmod, void **thr_data);

/**
 * Release any thread-specific resources acquired by nmsg_fltmod_thread_init().
 * Calls the module's 'thread_fini' function.
 *
 * \param fltmod
 *	Initialized fltmod.
 *
 * \param thr_data
 *	Opaque data pointer originally returned by nmsg_fltmod_thread_init().
 *
 * \return #nmsg_res_success
 *	If the thread data was successfully released.
 * \return
 *	Any other result may be returned by the module's 'thread_fini' function
 *	to indicate an error.
 */
nmsg_res
nmsg_fltmod_thread_fini(nmsg_fltmod_t fltmod, void *thr_data);

/**
 * Filter a message object and return the filter verdict. Calls the module's
 * 'filter_message' function.
 *
 * The thread that calls this function must have first called
 * nmsg_fltmod_thread_init(), and the 'thr_data' value returned by that
 * function must be passed as the 'thr_data' parameter to this function.
 *
 * \param fltmod
 *	Initialized fltmod.
 *
 * \param[in,out] msg
 *	The NMSG message object to be filtered. The filter function may alter
 *	the message object, or it may replace it with a new message object.
 *
 * \param thr_data
 *	Opaque data pointer originally returned by nmsg_fltmod_thread_init().
 *
 * \param[out] vres
 *	The filter verdict. \see #nmsg_filter_message_verdict for the possible
 *	verdict results and meanings.
 *
 * \return #nmsg_res_success
 *	The filtering completed and returned a verdict in 'vres'.
 * \return
 *	Any other result may be returned to indicate a fatal error.
 */
nmsg_res
nmsg_fltmod_filter_message(nmsg_fltmod_t fltmod,
			   nmsg_message_t *msg,
			   void *thr_data,
			   nmsg_filter_message_verdict *vres);

#endif /* NMSG_FLTMOD_H */
