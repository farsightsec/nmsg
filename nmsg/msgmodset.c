/*
 * Copyright (c) 2008-2010, 2012, 2013 by Farsight Security, Inc.
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

#include <dirent.h>
#include <dlfcn.h>

#include "private.h"

/* Forward. */

static nmsg_res msgmodset_load_module(struct nmsg_msgmodset *,
				      struct nmsg_msgmod_plugin *,
				      const char *fname);

static void msgmodset_insert_module(struct nmsg_msgmodset *, struct nmsg_msgmod *);

/* Internal functions. */

/* XXX: factor out the non-msgmod functionality of nmsg_msgmodset_init() and
 * nmsg_msgmodset_destroy() */

struct nmsg_msgmodset *
_nmsg_msgmodset_init(const char *plugin_path) {
	nmsg_res res = nmsg_res_failure;
	int oldwd;
	DIR *dir = NULL;
	struct dirent *de = NULL;
	struct nmsg_msgmodset *msgmodset = NULL;

	assert(plugin_path != NULL);

	if (_nmsg_global_debug >= 2)
		fprintf(stderr, "%s: loading modules from %s\n", __func__,
			plugin_path);

	oldwd = open(".", O_RDONLY);
	if (oldwd == -1) {
		perror("open");
		goto out;
	}

	msgmodset = calloc(1, sizeof(*msgmodset));
	assert(msgmodset != NULL);
	msgmodset->vendors = calloc(1, sizeof(void *));
	assert(msgmodset->vendors != NULL);

	if (chdir(plugin_path) != 0) {
		perror("chdir(plugin_path)");
		res = nmsg_res_success;
		goto out;
	}

	dir = opendir(plugin_path);
	if (dir == NULL) {
		perror("opendir");
		goto out;
	}
	while ((de = readdir(dir)) != NULL) {
		char *fn;
		size_t fnlen;
		struct nmsg_dlmod *dlmod;
		struct nmsg_msgmod_plugin *plugin;
		struct nmsg_msgmod_plugin **plugin_array;
		struct stat statbuf;

		if (stat(de->d_name, &statbuf) == -1)
			continue;
		if (!S_ISREG(statbuf.st_mode))
			continue;
		fn = de->d_name;
		fnlen = strlen(fn);
		if (fnlen > 3 &&
		    !(fn[fnlen - 3] == '.' &&
		      fn[fnlen - 2] == 's' &&
		      fn[fnlen - 1] == 'o'))
		{
			/* XXX: platforms that don't use ".so" */

			/* not a module, skip */
			continue;
		}
		if (strstr(fn, NMSG_MSG_MODULE_PREFIX "_isc.") == fn) {
			/* XXX: if the base msgmodset plugin is present under its
			 * old "ISC" name, silently skip it */
			continue;
		}
		if (strstr(fn, NMSG_MSG_MODULE_PREFIX "_") == fn) {
			if (_nmsg_global_debug >= 4)
				fprintf(stderr, "%s: trying %s\n", __func__, fn);
			dlmod = _nmsg_dlmod_init(fn);
			if (dlmod == NULL) {
				perror("_nmsg_dlmod_init");
				goto out;
			}
			if (_nmsg_global_debug >= 4)
				fprintf(stderr, "%s: loading nmsg message module %s\n",
					__func__, fn);

			plugin = (struct nmsg_msgmod_plugin *)
				dlsym(dlmod->handle, "nmsg_msgmod_ctx");
			if (plugin == NULL)
				dlerror();

			plugin_array = (struct nmsg_msgmod_plugin **)
				dlsym(dlmod->handle, "nmsg_msgmod_ctx_array");
			if (plugin_array == NULL)
				dlerror();

			if (plugin == NULL && plugin_array == NULL) {
				fprintf(stderr, "%s: WARNING: no modules found,"
					" not loading %s\n", __func__, fn);
				_nmsg_dlmod_destroy(&dlmod);
				continue;
			}

			dlmod->type = nmsg_modtype_msgmod;
			ISC_LIST_APPEND(msgmodset->dlmods, dlmod, link);

			if (plugin != NULL) {
				res = msgmodset_load_module(msgmodset, plugin, fn);
				if (res != nmsg_res_success)
					goto out;
			}

			if (plugin_array != NULL) {
				unsigned i = 0;

				for (i = 0, plugin = plugin_array[i];
				     plugin != NULL;
				     i++, plugin = plugin_array[i])
				{
					res = msgmodset_load_module(msgmodset,
								    plugin,
								    fn);
					if (res != nmsg_res_success)
						goto out;
				}
			}
		}
	}
	res = nmsg_res_success;
out:
	if (res != nmsg_res_success && msgmodset != NULL)
		_nmsg_msgmodset_destroy(&msgmodset);
	if (dir != NULL)
		(void) closedir(dir);
	(void) fchdir(oldwd);
	(void) close(oldwd);
	return (msgmodset);
}

void
_nmsg_msgmodset_destroy(struct nmsg_msgmodset **pms) {
	struct nmsg_dlmod *dlmod, *dlmod_next;
	struct nmsg_msgmod *mod;
	struct nmsg_msgmodset *ms;
	struct nmsg_msgvendor *msgv;
	unsigned vid, msgtype;

	ms = *pms;
	if (ms == NULL)
		return;

	dlmod = ISC_LIST_HEAD(ms->dlmods);
	while (dlmod != NULL) {
		dlmod_next = ISC_LIST_NEXT(dlmod, link);
		_nmsg_dlmod_destroy(&dlmod);
		dlmod = dlmod_next;
	}
	for (vid = 0; vid <= ms->nv; vid++) {
		msgv = ms->vendors[vid];
		if (msgv == NULL)
			continue;

		for (msgtype = 0; msgtype <= msgv->nm; msgtype++) {
			mod = msgv->msgtypes[msgtype];
			if (mod != NULL)
				_nmsg_msgmod_stop(&mod);
		}
		free(msgv->msgtypes);
		free(msgv);
	}
	free(ms->vendors);
	free(ms);
	*pms = NULL;
}

/* Private functions. */

static nmsg_res
msgmodset_load_module(struct nmsg_msgmodset *ms, struct nmsg_msgmod_plugin *plugin,
		      const char *fname)
{
	struct nmsg_msgmod *msgmod;

	if (plugin->msgver != NMSG_MSGMOD_VERSION) {
		fprintf(stderr, "%s: WARNING: version mismatch, not loading %s\n",
				__func__, fname);
		return (nmsg_res_failure);
	}

	if (plugin->sizeof_ProtobufCMessageDescriptor != sizeof(ProtobufCMessageDescriptor) ||
	    plugin->sizeof_ProtobufCFieldDescriptor != sizeof(ProtobufCFieldDescriptor) ||
	    plugin->sizeof_ProtobufCEnumDescriptor != sizeof(ProtobufCEnumDescriptor))
	{
		fprintf(stderr, "%s: WARNING: descriptor structure size mismatch, not loading %s\n",
			__func__, fname);
		return (nmsg_res_failure);
	}

	msgmod = _nmsg_msgmod_start(plugin);
	if (msgmod == NULL) {
		if (_nmsg_global_debug >= 1) {
			fprintf(stderr, "%s: unable to load message type %s/%s from %s\n",
				__func__, plugin->vendor.name, plugin->msgtype.name,
				fname);
		}
		return (nmsg_res_failure);
	}
	msgmodset_insert_module(ms, msgmod);
	if (_nmsg_global_debug >= 3)
		fprintf(stderr, "%s: loaded message schema %s/%s from %s "
			"@ %p\n", __func__,
			plugin->vendor.name, plugin->msgtype.name,
			fname, plugin);
	else if (_nmsg_global_debug == 2)
		fprintf(stderr, "%s: loaded message schema %s/%s\n",
			__func__, plugin->vendor.name, plugin->msgtype.name);

	return (nmsg_res_success);
}

static void
msgmodset_insert_module(struct nmsg_msgmodset *ms, struct nmsg_msgmod *mod) {
	struct nmsg_msgvendor *msgv;
	unsigned i, vid, max_msgtype;

	vid = mod->plugin->vendor.id;
	max_msgtype = mod->plugin->msgtype.id;

	if (ms->nv < vid) {
		/* resize vendor array */
		size_t vsz = sizeof(void *) * (vid + 1);
		ms->vendors = realloc(ms->vendors, vsz);
		assert(ms->vendors != NULL);
		for (i = ms->nv + 1; i <= vid; i++)
			ms->vendors[i] = NULL;
		ms->nv = vid;
	}
	if (ms->vendors[vid] == NULL) {
		/* previously unseen vendor id */
		ms->vendors[vid] = calloc(1, sizeof(struct nmsg_msgvendor));
		assert(ms->vendors[vid] != NULL);
		ms->vendors[vid]->msgtypes = calloc(1, sizeof(void *));
		assert(ms->vendors[vid]->msgtypes != NULL);
	}
	msgv = ms->vendors[vid];
	if (msgv->nm < max_msgtype) {
		/* resize msgtype array */
		size_t msz = sizeof(void *) * (max_msgtype + 1);
		msgv->msgtypes = realloc(msgv->msgtypes, msz);
		assert(msgv->msgtypes != NULL);
		for (i = msgv->nm + 1; i <= max_msgtype; i++)
			msgv->msgtypes[i] = NULL;
		msgv->nm = max_msgtype;
	}
	if (msgv->msgtypes[mod->plugin->msgtype.id] != NULL)
		fprintf(stderr, "%s: WARNING: already loaded module for "
			"vendor id %u, message type %u\n", __func__,
			mod->plugin->vendor.id, mod->plugin->msgtype.id);
	msgv->msgtypes[mod->plugin->msgtype.id] = mod;
}
