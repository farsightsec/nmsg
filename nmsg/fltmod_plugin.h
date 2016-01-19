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

#ifndef NMSG_FLTMOD_PLUGIN_H
#define NMSG_FLTMOD_PLUGIN_H

/*! \file nmsg/fltmod_plugin.h
 * \brief Implementing message filter modules.
 *
 * This file defines the interface that developers of message filter modules
 * must implement. For the interface for loading and calling filter modules,
 * see nmsg/fltmod.h.
 *
 * Filter modules are dynamically loaded shared objects that must export a
 * symbol called <tt>nmsg_fltmod_plugin_export</tt>. This is a structure of
 * type #nmsg_fltmod_plugin and is the sole entry point into the module.
 *
 * The first field of the nmsg_fltmod_plugin structure is the version of the
 * API/ABI between libnmsg and the filter module. Module developers should
 * assign this field the value #NMSG_FLTMOD_VERSION, or they can add
 * <tt>NMSG_FLTMOD_REQUIRED_INIT,</tt> to the initializer, which is a
 * convenience macro that initializes required fields.
 *
 * A filter module needs to provide at least one function, the core message
 * filtering function <tt>filter_message</tt>. This function must be
 * thread-safe, since it may be called simultaneously from multiple threads.
 *
 * Optionally, up to four more functions may be provided: a global module
 * initializer and finalizer (<tt>module_init</tt> and <tt>module_fini</tt>),
 * and a per-thread initializer and finalizer (<tt>thread_init</tt> and
 * <tt>thread_fini</tt>). These functions can be used to acquire and release
 * resources, generate debug messages, etc. The module and thread initializers
 * may provide opaque data pointers. These pointers will be provided as
 * parameters to the message filtering function.
 *
 * The <tt>module_init</tt> function will only be called once, immediately
 * after the plugin module has been loaded. It will be called before all other
 * module functions. Therefore, it does not need to be thread-safe.
 *
 * The <tt>module_fini</tt> function will only be called once, immediately
 * before the plugin module will be unloaded from the process. It will be
 * called after all other module functions. Therefore, it does not need to be
 * thread-safe, either.
 *
 * The <tt>thread_init</tt> and <tt>thread_fini</tt> functions may be called by
 * a processing thread after the thread has started and before the thread
 * exits. They need to be thread-safe, since they be called by independently
 * executing threads. A thread may not call a module's <tt>filter_message</tt>
 * function before it has called <tt>thread_init</tt>, and it may not call
 * <tt>filter_message</tt> after it has called <tt>thread_fini</tt>.
 *
 * For an example of a simple message filtering module, see the "sample" filter
 * module in the fltmod/ directory of the nmsg distribution. The "sample"
 * filter performs either systematic count-based or uniform probabilistic
 * sampling of the message stream.
 */

#include <nmsg.h>

/** Version number of the nmsg fltmod ABI. */
#define NMSG_FLTMOD_VERSION	1

/**
 * Initialize the filter module.
 *
 * Data with module-defined meaning may be passed in via the 'param' and
 * 'len_param' parameters. This can be used to, for example, configure
 * module-specific filtering parameters.
 *
 * \param[in] param
 *	Module-defined data needed for the initialization of the module.
 *
 * \param[in] len_param
 *	Length of 'param'.
 *
 * \param[out] mod_data
 *	Module-defined, module-wide state, passed to other module functions
 *	that take a 'mod_data' parameter.
 *
 * \return #nmsg_res_success
 *	If the module was successfully initialized.
 * \return
 *	Any other result to indicate a fatal error.
 */
typedef nmsg_res
(*nmsg_fltmod_module_init_fp)(const void *param,
			      const size_t len_param,
			      void **mod_data);

/**
 * Destroy the filter module. Any module-wide resources acquired by the module
 * must be released.
 *
 * \param[in] mod_data
 *	Module-defined, module-wide state.
 */
typedef void
(*nmsg_fltmod_module_fini_fp)(void *mod_data);

/**
 * Initialize module-defined, thread-wide state.
 *
 * \param[in] mod_data
 *	Module-defined, module-wide state.
 *
 * \param[out] thr_data
 *	Module-defined, thread-wide state.
 *
 * \return #nmsg_res_success
 *	If the thread-wide state was successfully initialized.
 * \return
 *	Any other result to indicate a fatal error.
 */
typedef nmsg_res
(*nmsg_fltmod_thread_init_fp)(void *mod_data, void **thr_data);

/**
 * Destroy thread-wide state. Any thread-wide resources corresponding to the
 * passed in 'thr_data' value that have been acquired by the module must be
 * released.
 *
 * \param[in] mod_data
 *	Module-defined, module-wide state.
 *
 * \param[in] thr_data
 *	Module-defined, thread-wide state.
 *
 * \return #nmsg_res_success
 *	If the thread-wide state was successfully destroyed.
 * \return
 *	Any other result to indicate a fatal error.
 */
typedef nmsg_res
(*nmsg_fltmod_thread_fini_fp)(void *mod_data, void *thr_data);

/**
 * Filter a message object and return the filter verdict.
 *
 * The filter function may alter the message object, or it may replace the
 * message object with an entirely new message. If the filter function replaces
 * the message object, it is responsible for disposing of the old message, for
 * instance by calling nmsg_message_destroy().
 *
 * \param[in,out] msg
 *	Pointer to the message object to be filtered. The message object may
 *	optionally be altered, or it may be replaced with an entirely new
 *	message object.
 *
 * \param[in] mod_data
 *	Module-defined, module-wide state.
 *
 * \param[in] thr_data
 *	Module-defined, thread-wide state.
 *
 * \param[out] vres
 *	The filter verdict. \see #nmsg_filter_message_verdict for the possible
 *	verdict results and meanings.
 *
 * \return #nmsg_res_success
 *      The filtering completed and returned a verdict in 'vres'.
 * \return
 *	Any other result to indicate a fatal error.
 */
typedef nmsg_res
(*nmsg_fltmod_filter_message_fp)(nmsg_message_t *msg,
				 void *mod_data,
				 void *thr_data,
				 nmsg_filter_message_verdict *vres);

/** Convenience macro. */
#define NMSG_FLTMOD_REQUIRED_INIT \
	.fltmod_version = NMSG_FLTMOD_VERSION

/**
 * Structure exported by filter modules.
 */
struct nmsg_fltmod_plugin {
	/**
	 * Module interface version.
	 * Must be set to #NMSG_FLTMOD_VERSION or the module will be rejected
	 * at load time.
	 */
	long					fltmod_version;

	/**
	 * Module-wide initialization function. Optional, may be NULL. If this
	 * function exists, it will be called once at module startup by
	 * nmsg_fltmod_init().
	 */
	nmsg_fltmod_module_init_fp		module_init;

	/**
	 * Module-wide finalization function. Optional, may be NULL. If this
	 * function exists, it will be called once at module shutdown by
	 * nmsg_fltmod_destroy(). This function should clean up any resources
	 * acquired by 'module_init'.
	 */
	nmsg_fltmod_module_fini_fp		module_fini;

	/**
	 * Per-thread initialization function. Optional, may be NULL. If this
	 * function exists, it will be called by each thread that wants to
	 * perform message filtering via nmsg_fltmod_thread_init().
	 */
	nmsg_fltmod_thread_init_fp		thread_init;

	/**
	 * Per-thread finalization function. Optional, may be NULL. If this
	 * function exists, it will be called by each thread that has called
	 * 'thread_init' before the thread exits by nmsg_fltmod_thread_fini().
	 * This function should clean up any resources acquired by
	 * 'thread_init'.
	 */
	nmsg_fltmod_thread_fini_fp		thread_fini;

	/**
	 * Message filter function. Required, must not be NULL. This function
	 * is called by nmsg_fltmod_filter_message().
	 */
	nmsg_fltmod_filter_message_fp		filter_message;

	/**
	 * \private Reserved fields.
	 */
	void					*_reserved15;
	void					*_reserved14;
	void					*_reserved13;
	void					*_reserved12;
	void					*_reserved11;
	void					*_reserved10;
	void					*_reserved9;
	void					*_reserved8;
	void					*_reserved7;
	void					*_reserved6;
	void					*_reserved5;
	void					*_reserved4;
	void					*_reserved3;
	void					*_reserved2;
	void					*_reserved1;
	void					*_reserved0;
};

#endif /* NMSG_FLTMOD_PLUGIN_H */
