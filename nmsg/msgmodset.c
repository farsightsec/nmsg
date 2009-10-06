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

/* Data structures. */

struct nmsg_msgvendor {
	struct nmsg_msgmod		**msgtypes;
	char				*vname;
	size_t				nm;
};

struct nmsg_msgmodset {
	ISC_LIST(struct nmsg_dlmod)	dlmods;
	struct nmsg_msgvendor		**vendors;
	size_t				nv;
	int				debug;
};

/* Forward. */

static nmsg_res msgmodset_load_module(nmsg_msgmodset_t, struct nmsg_msgmod *,
				      const char *fname, int debug);

static void msgmodset_insert_module(nmsg_msgmodset_t, struct nmsg_msgmod *);

/* Export. */

/* XXX: factor out the non-msgmod functionality of nmsg_msgmodset_init() and
 * nmsg_msgmodset_destroy() */

nmsg_msgmodset_t
nmsg_msgmodset_init(const char *path, int debug) {
	DIR *dir;
	char *oldwd;
	long pathsz;
	nmsg_msgmodset_t msgmodset;
	nmsg_res res;
	struct dirent *de;

	if (path == NULL)
		path = NMSG_LIBDIR;

	if (debug >= 2)
		fprintf(stderr, "%s: loading modules from %s\n", __func__,
			path);

	msgmodset = calloc(1, sizeof(*msgmodset));
	assert(msgmodset != NULL);
	msgmodset->debug = debug;
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
		struct nmsg_msgmod *msgmod;
		struct nmsg_msgmod **msgmod_array;
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
		if (strstr(fn, NMSG_PBUF_MODULE_PREFIX "_") == fn) {
			if (debug >= 4)
				fprintf(stderr, "%s: trying %s\n", __func__, fn);
			dlmod = _nmsg_dlmod_init(fn);
			if (dlmod == NULL) {
				perror("_nmsg_dlmod_init");
				free(msgmodset);
				free(oldwd);
				(void) closedir(dir);
				return (NULL);
			}
			if (debug >= 4)
				fprintf(stderr, "%s: loading nmsgpb module %s\n",
					__func__, fn);
			msgmod = (struct nmsg_msgmod *)
				dlsym(dlmod->handle, "nmsg_msgmod_ctx");
			msgmod_array = (struct nmsg_msgmod **)
				dlsym(dlmod->handle, "nmsg_msgmod_ctx_array");
			if (msgmod != NULL &&
			    msgmod->msgver != NMSG_MSGMOD_VERSION)
			{
				fprintf(stderr, "%s: WARNING: version mismatch,"
						" not loading %s\n",
						__func__, fn);
				_nmsg_dlmod_destroy(&dlmod);
				continue;
			}

			if (msgmod == NULL && msgmod_array == NULL) {
				fprintf(stderr, "%s: WARNING: no modules found,"
					" not loading %s\n", __func__, fn);
				_nmsg_dlmod_destroy(&dlmod);
				continue;
			}

			dlmod->type = nmsg_modtype_pbuf;
			ISC_LIST_APPEND(msgmodset->dlmods, dlmod, link);

			if (msgmod != NULL) {
				res = msgmodset_load_module(msgmodset, msgmod,
							    fn, debug);
				if (res != nmsg_res_success)
					goto out;
			}

			if (msgmod_array != NULL) {
				unsigned i = 0;

				for (i = 0, msgmod = msgmod_array[i];
				     msgmod != NULL;
				     i++, msgmod = msgmod_array[i])
				{
					res = msgmodset_load_module(msgmodset,
								    msgmod,
								    fn, debug);
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
nmsg_msgmodset_destroy(nmsg_msgmodset_t *pms) {
	struct nmsg_dlmod *dlmod, *dlmod_next;
	nmsg_msgmodset_t ms;
	unsigned i;

	ms = *pms;
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

nmsg_msgmod_t
nmsg_msgmodset_lookup(nmsg_msgmodset_t ms, unsigned vid, unsigned msgtype) {
	struct nmsg_msgmod *mod;
	struct nmsg_msgvendor *msgv;

	if (vid <= ms->nv) {
		msgv = ms->vendors[vid];
		if (msgv != NULL && msgtype <= msgv->nm) {
			mod = msgv->msgtypes[msgtype];
			return (mod);
		}
	}

	return (NULL);
}

nmsg_msgmod_t
nmsg_msgmodset_lookup_byname(nmsg_msgmodset_t ms, const char *vname,
			     const char *mname)
{
	unsigned vid = 0;
	unsigned msgtype = 0;

	vid = nmsg_msgmodset_vname_to_vid(ms, vname);
	msgtype = nmsg_msgmodset_mname_to_msgtype(ms, vid, mname);

	if (vid == 0 || msgtype == 0)
		return (NULL);

	return (nmsg_msgmodset_lookup(ms, vid, msgtype));
}

unsigned
nmsg_msgmodset_vname_to_vid(nmsg_msgmodset_t ms, const char *vname) {
	unsigned i, j;

	for (i = 0; i <= ms->nv; i++) {
		struct nmsg_msgvendor *msgv;
		msgv = ms->vendors[i];

		if (msgv != NULL) {
			for (j = 0; j <= msgv->nm; j++) {
				struct nmsg_msgmod *mod;
				mod = msgv->msgtypes[j];

				if (mod != NULL &&
				    strcasecmp(mod->vendor.name, vname) == 0)
					return (mod->vendor.id);
			}
		}
	}
	return (0);
}

unsigned
nmsg_msgmodset_mname_to_msgtype(nmsg_msgmodset_t ms, unsigned vid, const char *mname) {
	unsigned i;

	if (vid <= ms->nv) {
		struct nmsg_msgvendor *msgv;

		msgv = ms->vendors[vid];
		if (msgv == NULL)
			return (0);
		for (i = 0; i <= msgv->nm; i++) {
			struct nmsg_msgmod *mod;

			mod = msgv->msgtypes[i];
			if (mod != NULL) {
				if (strcasecmp(mod->msgtype.name, mname) == 0)
					return (mod->msgtype.id);
			}
		}
	}

	return (0);
}

const char *
nmsg_msgmodset_vid_to_vname(nmsg_msgmodset_t ms, unsigned vid) {
	struct nmsg_msgvendor *msgv;
	unsigned i;

	if (vid > ms->nv)
		return (NULL);
	msgv = ms->vendors[vid];
	if (msgv == NULL)
		return (NULL);
	for (i = 0; i <= msgv->nm; i++) {
		struct nmsg_msgmod *mod;

		mod = msgv->msgtypes[i];
		if (mod != NULL && mod->vendor.id == vid)
			return (mod->vendor.name);
	}
	return (NULL);
}

const char *
nmsg_msgmodset_msgtype_to_mname(nmsg_msgmodset_t ms, unsigned vid,
			       unsigned msgtype)
{
	struct nmsg_msgvendor *msgv;
	unsigned i;

	if (vid > ms->nv)
		return (NULL);
	msgv = ms->vendors[vid];
	if (msgv == NULL)
		return (NULL);
	for (i = 0; i <= msgv->nm; i++) {
		struct nmsg_msgmod *mod;

		mod = msgv->msgtypes[i];
		if (mod != NULL && mod->vendor.id == vid) {
			if (mod->msgtype.id == msgtype)
				return (mod->msgtype.name);
		}
	}
	return (NULL);
}

/* Private. */

static nmsg_res
msgmodset_load_module(nmsg_msgmodset_t ms, struct nmsg_msgmod *msgmod,
		      const char *fname, int debug)
{
	nmsg_res res;

	res = _nmsg_msgmod_start(msgmod);
	if (res != nmsg_res_success) {
		if (debug >= 1)
			fprintf(stderr, "%s: unable to load module from %s\n",
				__func__, fname);
		return (res);
	}
	msgmodset_insert_module(ms, msgmod);
	if (debug >= 3)
		fprintf(stderr, "%s: loaded message schema %s/%s from %s "
			"@ %p\n", __func__,
			msgmod->vendor.name, msgmod->msgtype.name,
			fname, msgmod);
	else if (debug == 2)
		fprintf(stderr, "%s: loaded message schema %s/%s\n",
			__func__, msgmod->vendor.name, msgmod->msgtype.name);

	return (nmsg_res_success);
}

static void
msgmodset_insert_module(nmsg_msgmodset_t ms, struct nmsg_msgmod *mod) {
	struct nmsg_msgvendor *msgv;
	unsigned i, vid, max_msgtype;

	vid = mod->vendor.id;
	max_msgtype = mod->msgtype.id;

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
	if (msgv->msgtypes[mod->msgtype.id] != NULL)
		fprintf(stderr, "%s: WARNING: already loaded module for "
			"vendor id %u, message type %u\n", __func__,
			mod->vendor.id, mod->msgtype.id);
	msgv->msgtypes[mod->msgtype.id] = mod;
}
