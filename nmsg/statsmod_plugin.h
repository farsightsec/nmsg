/*
 * Copyright (c) 2024 by Domaintools, LLC.
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

#ifndef NMSG_STATSMOD_PLUGIN_H
#define NMSG_STATSMOD_PLUGIN_H

/*! \file nmsg/statsmod_plugin.h
 * \brief Implementing statistics export modules.
 *
 * This file defines the interface that developers of statistics export modules
 * must implement. For the interface for loading and calling statistics modules,
 * see nmsg/fltmod.h.
 *
 * Statistics modules are dynamically loaded shared objects that must export a
 * symbol called <tt>nmsg_statsmod_plugin_export</tt>. This is a structure of
 * type #nmsg_statsmod_plugin and is the sole entry point into the module.
 *
 * The first field of the nmsg_statsmod_plugin structure is the version of the
 * API/ABI between libnmsg and the statistics module. Module developers should
 * assign this field the value #NMSG_STATSMOD_VERSION, or they can add
 * <tt>NMSG_STATSMOD_REQUIRED_INIT,</tt> to the initializer, which is a
 * convenience macro that initializes required fields.
 *
 * A statistics module (statsmod) needs to provide four functions:
 *  1. An initialization function function <tt>module_init</tt>,
 *  2. A finalization function <tt>module_fini<tt>,
 *  3. A function to add an nmsg_io to instrumentation <tt>io_add</tt>, and
 *  4. A function to remove an nmsg_io from instrumentation <tt>io_remove</tt>.
 *
 * A statistics module is expected to call `nmsg_io_get_stats()` on any enrolled
 * nmsg_io object and expose these stats appropriately.
 */

#include <nmsg.h>

/** Version number of the nmsg statsmod ABI. */
#define NMSG_STATSMOD_VERSION	1

/**
 * Initialize the stats module.
 *
 * Data with module-defined meaning may be passed in via the 'param' and
 * 'len_param' parameters. This can be used to, for example, configure
 * module-specific statistics export parameters.
 *
 * \param[in] io
 *	nmsg_io_t object to instrument.
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
(*nmsg_statsmod_module_init_fp)(const void *param,
				size_t len_param,
				void **mod_data);

/**
 * Destroy the filter module. Any module-wide resources acquired by the module
 * must be released.
 *
 * \param[in] mod_data
 *	Module-defined, module-wide state.
 */
typedef void
(*nmsg_statsmod_module_fini_fp)(void *mod_data);

/**
 * Add an `nmsg_io_t` with the statistics module for instrumentation.
 *
 * \param[in] mod_data
 *	Module-defined, module-wide state.
 *
 * \param[in] io
 *	An nmsg_io_t object.
 *
 * \param[in] name
 *	A name for the nmsg_io_t object to appear in stats reporting.
 */
typedef nmsg_res
(*nmsg_statsmod_add_io_fp)(void *mod_data, nmsg_io_t io, const char *name);

/**
 * Remove an `nmsg_io_t` with the filter module. Must be called before
 * nmsg_io_destroy() on the given io object.
 *
 * \param[in] mod_data
 *	Module-defined, module-wide state.
 *
 * \param[in] io
 *	An nmsg_io_t object.
 */
typedef nmsg_res
(*nmsg_statsmod_remove_io_fp)(void *mod_data, nmsg_io_t io);

/** Convenience macro. */
#define NMSG_STATSMOD_REQUIRED_INIT \
	.statsmod_version = NMSG_STATSMOD_VERSION

/**
 * Structure exported by statistics modules.
 */
struct nmsg_statsmod_plugin {
	/**
	 * Module interface version.
	 * Must be set to #NMSG_FLTMOD_VERSION or the module will be rejected
	 * at load time.
	 */
	long					statsmod_version;

	/**
	 * Module-wide initialization function. Required, must not be NULL.
	 * Called by nmsg_statsmod_init() on module startup.
	 */
	nmsg_statsmod_module_init_fp		module_init;

	/**
	 * Module-wide finalization function. Required, must not be NULL.
	 * Called once at module shutdown by nmsg_statsmod_destroy(). This
	 * function must release any resources acquired by 'module_init'.
	 */
	nmsg_statsmod_module_fini_fp		module_fini;

	/**
	 * Add an nmsg_io_t to statsmod instrumentation. Required, must not
	 * be NULL. Called prior to `nmsg_io_loop()` to export statistics
	 * through the statsmod.
	 */
	nmsg_statsmod_add_io_fp			io_add;

	/**
	 * Remove an nmsg_io_t from statsmod instrumentation. Required, must not
	 * be NULL.
	 */
	nmsg_statsmod_remove_io_fp		io_remove;

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

#endif /* NMSG_STATSMOD_PLUGIN_H */
