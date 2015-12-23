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

#include <nmsg.h>

/** Version number of the nmsg fltmod ABI. */
#define NMSG_FLTMOD_VERSION	1

/** \see nmsg_fltmod_init() */
typedef nmsg_res
(*nmsg_fltmod_module_init_fp)(const void *param,
			      const size_t len_param,
			      void **mod_data);

/** \see nmsg_fltmod_destroy() */
typedef void
(*nmsg_fltmod_module_fini_fp)(void *mod_data);

/** \see nmsg_fltmod_thread_init() */
typedef nmsg_res
(*nmsg_fltmod_thread_init_fp)(void *mod_data, void **thr_data);

/** \see nmsg_fltmod_thread_fini() */
typedef nmsg_res
(*nmsg_fltmod_thread_fini_fp)(void *mod_data, void *thr_data);

/** \see nmsg_fltmod_filter_message() */
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
