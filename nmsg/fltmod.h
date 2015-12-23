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
 * \brief Message filter modules.
 *
 * Message filter modules allow a message filtering function to be implemented
 * externally in a dynamically loaded plugin.
 *
 * Filter modules are dynamically loaded shared objects that must export a
 * symbol called <tt>nmsg_fltmod_plugin_export</tt>. This is a structure of type
 * #nmsg_fltmod_plugin and is the sole entry point into the module.
 *
 * The first field of the nmsg_fltmod_plugin structure is the version of the
 * API/ABI between libnmsg and the filter module. Module developers should
 * assign this field the value #NMSG_FLTMOD_VERSION, or they can add
 * <tt>NMSG_FLTMOD_REQUIRED_INIT,</tt> to the initializer, which is a
 * convenience macro that initializes required fields.
 *
 * A filter module needs to provide at least one function, the core message
 * filtering function <tt>message_filter</tt>. This function must be
 * thread-safe, since it may be called simultaneously from multiple threads.
 *
 * Optionally, up to four more functions may be provided: a global module
 * initializer and finalizer (<tt>module_init</tt> and <tt>module_fini</tt>),
 * and a per-thread initializer and finalizer (<tt>thread_init</tt> and
 * <tt>thread_fini</tt>). These functions can be used to acquire and release
 * resources, generate debug messages, etc. The module and thread initializers
 * may provide opaque data pointers via a parameter-return value. These pointers
 * will be provided as parameters to the message filtering function.
 *
 * The <tt>module_init</tt> function will only be called once, immediately after
 * the plugin module has been loaded. It will be called before all other module
 * functions. Therefore, it does not need to be thread-safe.
 *
 * The <tt>module_fini</tt> function will only be called once, immediately
 * before the plugin module will be unloaded from the process. It will be called
 * after all other module functions. Therefore, it does not need to be
 * thread-safe, either.
 *
 * The <tt>thread_init</tt> and <tt>thread_fini</tt> may be called by a
 * processing thread after the thread has started and before the thread exits.
 * They need to be thread-safe, since they be called by independently executing
 * threads. A thread may not call a module's <tt>message_filter</tt> function
 * before it has called <tt>thread_init</tt>, and it may not call
 * <tt>message_filter</tt> after it has called <tt>thread_fini</tt>.
 *
 * For an example of a simple message filtering module, see the "sample" filter
 * module in the fltmod/ directory of the nmsg distribution. The "sample" filter
 * performs either systematic count-based or uniform probabilistic sampling of
 * the message stream.
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
 */
nmsg_fltmod_t
nmsg_fltmod_init(const char *name, const void *param, const size_t len_param);

/**
 * Destroy a filter module. Calls the module's 'module_fini' function.
 *
 * \param[in] fltmod
 *	Initialized fltmod.
 */
void
nmsg_fltmod_destroy(nmsg_fltmod_t *fltmod);

/**
 * Initialize thread-specific data for the filter module. Must be called by a
 * processing thread before calling #nmsg_fltmod_filter_message(). Calls the
 * module's 'thread_init' function.
 *
 * \param fltmod
 *	Initialized fltmod.
 *
 * \param[out] thr_data
 *	Opaque data pointer specific to the calling thread. This pointer must be
 *	supplied in subsequent calls to #nmsg_fltmod_filter_message() or
 *	#nmsg_fltmod_thread_fini(). The caller must provide space to store this
 *	value.
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
 * Release any thread-specific resources acquired by #nmsg_fltmod_thread_init().
 * Calls the module's 'thread_fini' function.
 *
 * \param fltmod
 *	Initialized fltmod.
 *
 * \param thr_data
 *	Opaque data pointer originally returned by #nmsg_fltmod_thread_init().
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
 * Filter a message payload and return the filter verdict. Calls the module's
 * 'filter_message' function.
 *
 * \param fltmod
 *	Initialized fltmod.
 *
 * \param msg
 *	The NMSG message payload to be filtered.
 *
 * \param thr_data
 *	Opaque data pointer originally returned by #nmsg_fltmod_thread_init().
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
			   nmsg_message_t msg,
			   void *thr_data,
			   nmsg_filter_message_verdict *vres);

#endif /* NMSG_FLTMOD_H */
