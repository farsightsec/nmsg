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

#ifndef NMSG_STATSMOD_H
#define NMSG_STATSMOD_H

/*! \file nmsg/statsmod.h
 * \brief Loading and calling external statistics modules.
 *
 * This file defines the interface for loading and calling statistics modules. For
 * the interface that developers of message filter modules must implement, see
 * nmsg/statsmod_plugin.h.
 *
 * Statistics modules allow statistics from an nmsg_io_t to be exported to an
 * external metrics gathering system.
 */

/**
 * Initialize a statistics module with the given parameters. Calls the module's
 * 'module_init' function.
 *
 * \param name
 *	The name of the statistics module, which is used to construct the filesystem
 *	path to the shared object containing the module. This may either be a
 *	real, complete filesystem path (absolute or relative) that begins
 *	with "/" or "./", or it may be a short "convenience" name that will be
 *	expanded to a real filesystem path. For example, the short name "sample"
 *	might be expanded to a long name like
 *	"/usr/lib/nmsg/nmsg_stats1_sample.so".
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
nmsg_statsmod_t
nmsg_statsmod_init(const char *name, const void *param, const size_t len_param);

/**
 * Destroy a statistics module. Calls the module's 'module_fini' function.
 *
 * \param[in] statsmod
 *	Initialized statsmod.
 */
void
nmsg_statsmod_destroy(nmsg_statsmod_t *statsmod);

/**
 * Add an nmsg_io_t object to the statsmod instrumentation.
 *
 * \param statsmod
 * 	The stats module returned from nmsg_statsmod_init().
 *
 * \param io
 * 	The nmsg_io_t object to instrument.
 *
 * \param name
 *	A unique name to use when publishing stats for this io.
 */
nmsg_res
nmsg_statsmod_add_io(nmsg_statsmod_t statsmod, nmsg_io_t io, const char *name);

/**
 * Remove an nmsg_io_t object from statsmod instrumentation.
 *
 * Either `nmsg_statsmod_remove_io(io)` or `nmsg_statsmod_destroy(mod)`
 * must be called before `nmsg_io_destroy(io)`.
 *
 * \param statsmod
 * 	The stats module returned from nmsg_statsmod_init().
 *
 * \param io
 * 	The nmsg_io_t object to remove.
 */
nmsg_res
nmsg_statsmod_remove_io(nmsg_statsmod_t statsmod, nmsg_io_t io);

#endif /* NMSG_STATSMOD_H */
