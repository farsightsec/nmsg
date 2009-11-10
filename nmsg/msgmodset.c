/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include "nmsg_port.h"

#include <sys/stat.h>
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "private.h"

/* Forward. */

static nmsg_res msgmodset_load_module(nmsg_msgmodset_t,
				      struct nmsg_msgmod_plugin *,
				      const char *fname);

static void msgmodset_insert_module(nmsg_msgmodset_t, struct nmsg_msgmod *);

/* Export. */

/* XXX: factor out the non-msgmod functionality of nmsg_msgmodset_init() and
 * nmsg_msgmodset_destroy() */

struct nmsg_msgmodset *
_nmsg_msgmodset_init(const char *path) {
	DIR *dir;
	char *oldwd;
	long pathsz;
	nmsg_msgmodset_t msgmodset;
	nmsg_res res;
	struct dirent *de;

	if (path == NULL)
		path = NMSG_LIBDIR;

	if (_nmsg_global_debug >= 2)
		fprintf(stderr, "%s: loading modules from %s\n", __func__,
			path);

	msgmodset = calloc(1, sizeof(*msgmodset));
	assert(msgmodset != NULL);
	msgmodset->vendors = calloc(1, sizeof(void *));
	assert(msgmodset->vendors != NULL);

	pathsz = pathconf(".", _PC_PATH_MAX);
	if (pathsz < 0)
		pathsz = _POSIX_PATH_MAX;
	oldwd = getcwd(NULL, (size_t) pathsz);
	if (oldwd == NULL) {
		perror("getcwd");
		free(msgmodset);
		return (NULL);
	}
	if (chdir(path) != 0) {
		perror("chdir(path)");
		free(msgmodset);
		free(oldwd);
		return (NULL);
	}

	dir = opendir(path);
	if (dir == NULL) {
		perror("opendir");
		free(msgmodset);
		free(oldwd);
		return (NULL);
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
		if (strstr(fn, NMSG_MSG_MODULE_PREFIX "_") == fn) {
			if (_nmsg_global_debug >= 4)
				fprintf(stderr, "%s: trying %s\n", __func__, fn);
			dlmod = _nmsg_dlmod_init(fn);
			if (dlmod == NULL) {
				perror("_nmsg_dlmod_init");
				free(msgmodset);
				free(oldwd);
				(void) closedir(dir);
				return (NULL);
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

			if (plugin != NULL &&
			    plugin->msgver != NMSG_MSGMOD_VERSION)
			{
				fprintf(stderr, "%s: WARNING: version mismatch,"
						" not loading %s\n",
						__func__, fn);
				_nmsg_dlmod_destroy(&dlmod);
				continue;
			}

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
	if (chdir(oldwd) != 0) {
		perror("chdir(oldwd)");
		goto out;
	}
	free(oldwd);
	(void) closedir(dir);

	return (msgmodset);
out:
	free(msgmodset);
	free(oldwd);
	(void) closedir(dir);
	return (NULL);
}

void
_nmsg_msgmodset_destroy(struct nmsg_msgmodset **pms) {
	struct nmsg_dlmod *dlmod, *dlmod_next;
	struct nmsg_msgmodset *ms;
	unsigned i;

	ms = *pms;
	if (ms == NULL)
		return;

	dlmod = ISC_LIST_HEAD(ms->dlmods);
	while (dlmod != NULL) {
		dlmod_next = ISC_LIST_NEXT(dlmod, link);
		_nmsg_dlmod_destroy(&dlmod);
		dlmod = dlmod_next;
	}
	for (i = 0; i <= ms->nv; i++) {
		struct nmsg_msgvendor *msgv;
		msgv = ms->vendors[i];

		if (msgv != NULL) {
			free(msgv->msgtypes);
			free(msgv);
		}
	}
	free(ms->vendors);
	free(ms);
	*pms = NULL;
}

/* Private. */

static nmsg_res
msgmodset_load_module(nmsg_msgmodset_t ms, struct nmsg_msgmod_plugin *plugin,
		      const char *fname)
{
	struct nmsg_msgmod *msgmod;

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
msgmodset_insert_module(nmsg_msgmodset_t ms, struct nmsg_msgmod *mod) {
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
