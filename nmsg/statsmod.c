/*
 * Copyright (c) 2024 by Domaintools, LLC
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

/* Import. */

#include <dlfcn.h>

#include "private.h"

/* Private declarations .*/

/**
 * The name of the symbol inside the dlopen()'d module that exports the
 * plugin's struct nmsg_statsmod_plugin.
 */
#define NMSG_STATSMOD_ENTRY_POINT		"nmsg_statsmod_plugin_export"

struct nmsg_statsmod {
	struct nmsg_statsmod_plugin	*plugin;
	char				*fname;
	void				*dlhandle;
	void				*mod_data;
};

/* Private functions. */

static void *
nmsg__statsmod_dlopen(const char *filename, int flag)
{
	void *ret = dlopen(filename, flag);
	if (ret == NULL) {
		_nmsg_dprintf(4, "%s: dlopen() failed: %s\n", __func__, dlerror());
	}
	return ret;
}

static void
nmsg__statsmod_dlclose(void *handle)
{
	if (dlclose(handle) != 0) {
		_nmsg_dprintf(4, "%s: dlclose() failed: %s\n", __func__, dlerror());
	}
}

static void *
nmsg__statsmod_dlsym(void *handle, const char *symbol)
{
	/* Clear any old error condition. */
	dlerror();

	/* Call dlsym(). */
	void *ret = dlsym(handle, symbol);

	/* Check for an error. */
	char *err = dlerror();
	if (err != NULL) {
		_nmsg_dprintf(4, "%s: dlsym() failed: %s\n", __func__, err);
	}

	return ret;
}

/* Export. */

nmsg_statsmod_t
nmsg_statsmod_init(const char *name, const void *param, const size_t len_param)
{
	struct nmsg_statsmod *statsmod = my_calloc(1, sizeof(*statsmod));

	/**
	 * 'name' can be either an absolute or relative path (begins with "/"
	 * or ".") to a particular plugin file, or it can be a shorter human
	 * friendly name which we need to expand into a full file path.
	 */
	if (strlen(name) > 0 && name[0] != '/' && name[0] != '.') {
		/* Expand the short name into a full path name. */
		ubuf *u = ubuf_init(64);
		ubuf_add_fmt(u, "%s/%s_%s%s",
			     NMSG_PLUGINSDIR,
			     NMSG_STATS_MODULE_PREFIX,
			     name,
			     NMSG_MODULE_SUFFIX);
		statsmod->fname = my_strdup(ubuf_cstr(u));
		ubuf_destroy(&u);
	} else {
		/* Use 'name' as a full path name verbatim. */
		statsmod->fname = my_strdup(name);
	}

	/* Open a handle to the dynamic library file. */
	statsmod->dlhandle = nmsg__statsmod_dlopen(statsmod->fname, RTLD_LAZY);
	if (statsmod->dlhandle == NULL) {
		_nmsg_dprintf(1, "%s: ERROR: unable to open module file %s\n",
			      __func__, statsmod->fname);
		goto fail;
	}

	/* Check if the dynamic library file has our entry point. */
	statsmod->plugin = (struct nmsg_statsmod_plugin *)
		nmsg__statsmod_dlsym(statsmod->dlhandle, NMSG_STATSMOD_ENTRY_POINT);
	if (statsmod->plugin == NULL) {
		_nmsg_dprintf(1, "%s: WARNING: module '%s' missing entry point '%s', not loading\n",
			      __func__, statsmod->fname, NMSG_STATSMOD_ENTRY_POINT);
		goto fail;
	}

	/* Check if we support the plugin's ABI version. */
	if (statsmod->plugin->statsmod_version != NMSG_STATSMOD_VERSION) {
		_nmsg_dprintf(1, "%s: WARNING: module '%s' version mismatch, not loading\n",
			      __func__, statsmod->fname);
		goto fail;
	}

	/* Call the module initialization function. */
	nmsg_res res = statsmod->plugin->module_init(param, len_param, &statsmod->mod_data);
	if (res != nmsg_res_success) {
		_nmsg_dprintf(1, "%s: WARNING: module '%s' init failed with res %d (%s), "
			      "not loading\n",
			      __func__, statsmod->fname, res, nmsg_res_lookup(res));
		goto fail;
	}

	return statsmod;

fail:
	if (statsmod->dlhandle != NULL)
		nmsg__statsmod_dlclose(statsmod->dlhandle);
	free(statsmod->fname);
	free(statsmod);
	return NULL;
}

void
nmsg_statsmod_destroy(nmsg_statsmod_t *statsmod)
{
	/* Call the module finalization function. */
	(*statsmod)->plugin->module_fini((*statsmod)->mod_data);
	/* Close the handle to the dynamic library file. */
	nmsg__statsmod_dlclose((*statsmod)->dlhandle);

	my_free((*statsmod)->fname);
	my_free(*statsmod);
}

nmsg_res
nmsg_statsmod_add_io(nmsg_statsmod_t statsmod, nmsg_io_t io, const char *name)
{
	return statsmod->plugin->io_add(statsmod->mod_data, io, name);
}

nmsg_res
nmsg_statsmod_remove_io(nmsg_statsmod_t statsmod, nmsg_io_t io)
{
	return statsmod->plugin->io_remove(statsmod->mod_data, io);
}
