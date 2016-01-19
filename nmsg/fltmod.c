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

/* Import. */

#include <dlfcn.h>

#include "private.h"

/* Private declarations .*/

/**
 * The name of the symbol inside the dlopen()'d module that exports the
 * plugin's struct nmsg_fltmod_plugin.
 */
#define NMSG_FLTMOD_ENTRY_POINT		"nmsg_fltmod_plugin_export"

struct nmsg_fltmod {
	struct nmsg_fltmod_plugin	*plugin;
	char				*fname;
	void				*dlhandle;
	void				*mod_data;
};

/* Private functions. */

static void *
nmsg__fltmod_dlopen(const char *filename, int flag)
{
	void *ret = dlopen(filename, flag);
	if (ret == NULL) {
		_nmsg_dprintf(4, "%s: dlopen() failed: %s\n", __func__, dlerror());
	}
	return ret;
}

static void
nmsg__fltmod_dlclose(void *handle)
{
	if (dlclose(handle) != 0) {
		_nmsg_dprintf(4, "%s: dlclose() failed: %s\n", __func__, dlerror());
	}
}

static void *
nmsg__fltmod_dlsym(void *handle, const char *symbol)
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

nmsg_fltmod_t
nmsg_fltmod_init(const char *name, const void *param, const size_t len_param)
{
	struct nmsg_fltmod *fltmod = my_calloc(1, sizeof(*fltmod));

	/**
	 * 'name' can be either an absolute or relative path (begins with "/"
	 * or ".") to a particular plugin file, or it can be a shorter human
	 * friendly name which we need to expand into a full file path.
	 */
	if (strlen(name) > 0 && name[0] != '/' && name[0] != '.') {
		/* Expand the short name into a full path name. */
		ubuf *u = ubuf_init(64);
		ubuf_add_fmt(u, "%s/%s_%s%s",
			     NMSG_LIBDIR,
			     NMSG_FLT_MODULE_PREFIX,
			     name,
			     NMSG_MODULE_SUFFIX);
		fltmod->fname = my_strdup(ubuf_cstr(u));
		ubuf_destroy(&u);
	} else {
		/* Use 'name' as a full path name verbatim. */
		fltmod->fname = my_strdup(name);
	}

	/* Open a handle to the dynamic library file. */
	fltmod->dlhandle = nmsg__fltmod_dlopen(fltmod->fname, RTLD_LAZY);
	if (fltmod->dlhandle == NULL) {
		_nmsg_dprintf(1, "%s: ERROR: unable to open module file %s\n",
			      __func__, fltmod->fname);
		goto fail;
	}

	/* Check if the dynamic library file has our entry point. */
	fltmod->plugin = (struct nmsg_fltmod_plugin *)
		nmsg__fltmod_dlsym(fltmod->dlhandle, NMSG_FLTMOD_ENTRY_POINT);
	if (fltmod->plugin == NULL) {
		_nmsg_dprintf(1, "%s: WARNING: module '%s' missing entry point '%s', not loading\n",
			      __func__, fltmod->fname, NMSG_FLTMOD_ENTRY_POINT);
		goto fail;
	}

	/* Check if we support the plugin's ABI version. */
	if (fltmod->plugin->fltmod_version != NMSG_FLTMOD_VERSION) {
		_nmsg_dprintf(1, "%s: WARNING: module '%s' version mismatch, not loading\n",
			      __func__, fltmod->fname);
		goto fail;
	}

	/* Call the module initialization function. */
	if (fltmod->plugin->module_init != NULL) {
		nmsg_res res = fltmod->plugin->module_init(param, len_param, &fltmod->mod_data);
		if (res != nmsg_res_success) {
			_nmsg_dprintf(1, "%s: WARNING: module '%s' init failed with res %d (%s), "
				      "not loading\n",
				      __func__, fltmod->fname, res, nmsg_res_lookup(res));
			goto fail;
		}
	}

	return fltmod;

fail:
	if (fltmod->dlhandle != NULL)
		nmsg__fltmod_dlclose(fltmod->dlhandle);
	free(fltmod->fname);
	free(fltmod);
	return NULL;
}

void
nmsg_fltmod_destroy(nmsg_fltmod_t *fltmod)
{
	/* Call the module finalization function. */
	if ((*fltmod)->plugin->module_fini != NULL) {
		(*fltmod)->plugin->module_fini((*fltmod)->mod_data);
	}
	/* Close the handle to the dynamic library file. */
	nmsg__fltmod_dlclose((*fltmod)->dlhandle);

	my_free((*fltmod)->fname);
	my_free(*fltmod);
}

nmsg_res
nmsg_fltmod_thread_init(nmsg_fltmod_t fltmod, void **thr_data)
{
	if (fltmod->plugin->thread_init != NULL) {
		nmsg_res res = fltmod->plugin->thread_init(fltmod->mod_data, thr_data);
		if (res != nmsg_res_success) {
			_nmsg_dprintf(2, "%s: WARNING: module '%s' thread_init failed with res %d (%s)\n",
				      __func__, fltmod->fname, res, nmsg_res_lookup(res));
		}
		return res;
	}
	return nmsg_res_success;
}

nmsg_res
nmsg_fltmod_thread_fini(nmsg_fltmod_t fltmod, void *thr_data)
{
	if (fltmod->plugin->thread_fini != NULL) {
		nmsg_res res = fltmod->plugin->thread_fini(fltmod->mod_data, thr_data);
		if (res != nmsg_res_success) {
			_nmsg_dprintf(2, "%s: WARNING: module '%s' thread_fini failed with res %d (%s)\n",
				      __func__, fltmod->fname, res, nmsg_res_lookup(res));
		}
		return res;
	}
	return nmsg_res_success;
}

nmsg_res
nmsg_fltmod_filter_message(nmsg_fltmod_t fltmod,
			   nmsg_message_t *msg,
			   void *thr_data,
			   nmsg_filter_message_verdict *vres)
{
	if (fltmod->plugin->filter_message != NULL) {
		return fltmod->plugin->filter_message(msg, fltmod->mod_data, thr_data, vres);
	}
	return nmsg_res_notimpl;
}
