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

struct nmsg_pbvendor {
	struct nmsg_pbmod		**msgtypes;
	char				*vname;
	size_t				nm;
};

struct nmsg_pbmodset {
	ISC_LIST(struct nmsg_dlmod)	dlmods;
	struct nmsg_pbvendor		**vendors;
	size_t				nv;
	int				debug;
};

/* Forward. */

static void pbmodset_insert_module(nmsg_pbmodset_t, struct nmsg_pbmod *);

static void pbmodset_load_module(nmsg_pbmodset_t, struct nmsg_pbmod *,
				 const char *fname, int debug);

/* Export. */

/* XXX: factor out the non-pbmod functionality of nmsg_pbmodset_init() and
 * nmsg_pbmodset_destroy() */

nmsg_pbmodset_t
nmsg_pbmodset_init(const char *path, int debug) {
	DIR *dir;
	char *oldwd;
	long pathsz;
	nmsg_pbmodset_t pbmodset;
	struct dirent *de;

	pbmodset = calloc(1, sizeof(*pbmodset));
	assert(pbmodset != NULL);
	pbmodset->debug = debug;
	pbmodset->vendors = calloc(1, sizeof(void *));
	assert(pbmodset->vendors != NULL);

	pathsz = pathconf(".", _PC_PATH_MAX);
	if (pathsz < 0)
		pathsz = _POSIX_PATH_MAX;
	oldwd = getcwd(NULL, (size_t) pathsz);
	if (oldwd == NULL) {
		perror("getcwd");
		free(pbmodset);
		return (NULL);
	}
	if (chdir(path) != 0) {
		perror("chdir(path)");
		free(pbmodset);
		free(oldwd);
		return (NULL);
	}

	dir = opendir(path);
	if (dir == NULL) {
		perror("opendir");
		free(pbmodset);
		free(oldwd);
		return (NULL);
	}
	while ((de = readdir(dir)) != NULL) {
		char *fn;
		size_t fnlen;
		struct nmsg_dlmod *dlmod;
		struct nmsg_pbmod *pbmod;
		struct nmsg_pbmod **pbmod_array;
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
		dlmod = nmsg_dlmod_init(fn);
		if (dlmod == NULL) {
			perror("nmsg_dlmod_init");
			free(pbmodset);
			free(oldwd);
			(void) closedir(dir);
			return (NULL);
		}
		if (debug >= 4)
			fprintf(stderr, "%s: trying %s\n", __func__, fn);
		if (strstr(fn, NMSG_PBUF_MODULE_PREFIX "_") == fn) {
			if (debug >= 4)
				fprintf(stderr, "%s: loading nmsgpb module %s\n",
					__func__, fn);
			pbmod = (struct nmsg_pbmod *)
				dlsym(dlmod->handle, "nmsg_pbmod_ctx");
			pbmod_array = (struct nmsg_pbmod **)
				dlsym(dlmod->handle, "nmsg_pbmod_ctx_array");
			if (pbmod != NULL &&
			    pbmod->pbmver != NMSG_PBMOD_VERSION)
			{
				fprintf(stderr, "%s: WARNING: version mismatch,"
						" not loading %s\n",
						__func__, fn);
				nmsg_dlmod_destroy(&dlmod);
				continue;
			}

			if (pbmod == NULL && pbmod_array == NULL) {
				fprintf(stderr, "%s: WARNING: no modules found,"
					" not loading %s\n", __func__, fn);
				nmsg_dlmod_destroy(&dlmod);
				continue;
			}

			dlmod->type = nmsg_modtype_pbuf;
			ISC_LIST_APPEND(pbmodset->dlmods, dlmod, link);

			if (pbmod != NULL)
				pbmodset_load_module(pbmodset, pbmod,
						     fn, debug);

			if (pbmod_array != NULL) {
				unsigned i = 0;

				for (i = 0, pbmod = pbmod_array[i];
				     pbmod != NULL;
				     i++, pbmod = pbmod_array[i])
				{
					pbmodset_load_module(pbmodset, pbmod,
							     fn, debug);
				}
			}
		}
	}
	if (chdir(oldwd) != 0) {
		perror("chdir(oldwd)");
		free(pbmodset);
		free(oldwd);
		(void) closedir(dir);
		return (NULL);
	}
	free(oldwd);
	(void) closedir(dir);

	return (pbmodset);
}

void
nmsg_pbmodset_destroy(nmsg_pbmodset_t *pms) {
	struct nmsg_dlmod *dlmod, *dlmod_next;
	nmsg_pbmodset_t ms;
	unsigned i;

	ms = *pms;
	dlmod = ISC_LIST_HEAD(ms->dlmods);
	while (dlmod != NULL) {
		dlmod_next = ISC_LIST_NEXT(dlmod, link);
		nmsg_dlmod_destroy(&dlmod);
		dlmod = dlmod_next;
	}
	for (i = 0; i <= ms->nv; i++) {
		struct nmsg_pbvendor *pbv;
		pbv = ms->vendors[i];

		if (pbv != NULL) {
			free(pbv->msgtypes);
			free(pbv);
		}
	}
	free(ms->vendors);
	free(ms);
	*pms = NULL;
}

nmsg_pbmod_t
nmsg_pbmodset_lookup(nmsg_pbmodset_t ms, unsigned vid, unsigned msgtype) {
	struct nmsg_pbmod *mod;
	struct nmsg_pbvendor *pbv;

	if (vid <= ms->nv) {
		pbv = ms->vendors[vid];
		if (pbv != NULL && msgtype <= pbv->nm) {
			mod = pbv->msgtypes[msgtype];
			return (mod);
		}
	}

	return (NULL);
}

nmsg_pbmod_t
nmsg_pbmodset_lookup_byname(nmsg_pbmodset_t ms, const char *vname,
			    const char *mname)
{
	unsigned vid = 0;
	unsigned msgtype = 0;

	vid = nmsg_pbmodset_vname_to_vid(ms, vname);
	msgtype = nmsg_pbmodset_mname_to_msgtype(ms, vid, mname);

	if (vid == 0 || msgtype == 0)
		return (NULL);

	return (nmsg_pbmodset_lookup(ms, vid, msgtype));
}

unsigned
nmsg_pbmodset_vname_to_vid(nmsg_pbmodset_t ms, const char *vname) {
	unsigned i, j;

	for (i = 0; i <= ms->nv; i++) {
		struct nmsg_pbvendor *pbv;
		pbv = ms->vendors[i];

		if (pbv != NULL) {
			for (j = 0; j <= pbv->nm; j++) {
				struct nmsg_pbmod *mod;
				mod = pbv->msgtypes[j];

				if (mod != NULL &&
				    strcasecmp(mod->vendor.name, vname) == 0)
					return (mod->vendor.id);
			}
		}
	}
	return (0);
}

unsigned
nmsg_pbmodset_mname_to_msgtype(nmsg_pbmodset_t ms, unsigned vid, const char *mname) {
	unsigned i;

	if (vid <= ms->nv) {
		struct nmsg_pbvendor *pbv;

		pbv = ms->vendors[vid];
		if (pbv == NULL)
			return (0);
		for (i = 0; i <= pbv->nm; i++) {
			struct nmsg_pbmod *mod;

			mod = pbv->msgtypes[i];
			if (mod != NULL) {
				if (strcasecmp(mod->msgtype.name, mname) == 0)
					return (mod->msgtype.id);
			}
		}
	}

	return (0);
}

const char *
nmsg_pbmodset_vid_to_vname(nmsg_pbmodset_t ms, unsigned vid) {
	struct nmsg_pbvendor *pbv;
	unsigned i;

	if (vid > ms->nv)
		return (NULL);
	pbv = ms->vendors[vid];
	if (pbv == NULL)
		return (NULL);
	for (i = 0; i <= pbv->nm; i++) {
		struct nmsg_pbmod *mod;

		mod = pbv->msgtypes[i];
		if (mod != NULL && mod->vendor.id == vid)
			return (mod->vendor.name);
	}
	return (NULL);
}

const char *
nmsg_pbmodset_msgtype_to_mname(nmsg_pbmodset_t ms, unsigned vid,
			       unsigned msgtype)
{
	struct nmsg_pbvendor *pbv;
	unsigned i;

	if (vid > ms->nv)
		return (NULL);
	pbv = ms->vendors[vid];
	if (pbv == NULL)
		return (NULL);
	for (i = 0; i <= pbv->nm; i++) {
		struct nmsg_pbmod *mod;

		mod = pbv->msgtypes[i];
		if (mod != NULL && mod->vendor.id == vid) {
			if (mod->msgtype.id == msgtype)
				return (mod->msgtype.name);
		}
	}
	return (NULL);
}

/* Private. */

static void
pbmodset_load_module(nmsg_pbmodset_t ms, struct nmsg_pbmod *pbmod,
		     const char *fname, int debug)
{
	_nmsg_pbmod_start(pbmod);
	pbmodset_insert_module(ms, pbmod);
	if (debug >= 3)
		fprintf(stderr, "%s: loaded message schema %s/%s from %s "
			"@ %p\n", __func__,
			pbmod->vendor.name, pbmod->msgtype.name,
			fname, pbmod);
	else if (debug == 2)
		fprintf(stderr, "%s: loaded message schema %s/%s\n",
			__func__, pbmod->vendor.name, pbmod->msgtype.name);
}

static void
pbmodset_insert_module(nmsg_pbmodset_t ms, struct nmsg_pbmod *mod) {
	struct nmsg_pbvendor *pbv;
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
		ms->vendors[vid] = calloc(1, sizeof(struct nmsg_pbvendor));
		assert(ms->vendors[vid] != NULL);
		ms->vendors[vid]->msgtypes = calloc(1, sizeof(void *));
		assert(ms->vendors[vid]->msgtypes != NULL);
	}
	pbv = ms->vendors[vid];
	if (pbv->nm < max_msgtype) {
		/* resize msgtype array */
		size_t msz = sizeof(void *) * (max_msgtype + 1);
		pbv->msgtypes = realloc(pbv->msgtypes, msz);
		assert(pbv->msgtypes != NULL);
		for (i = pbv->nm + 1; i <= max_msgtype; i++)
			pbv->msgtypes[i] = NULL;
		pbv->nm = max_msgtype;
	}
	if (pbv->msgtypes[mod->msgtype.id] != NULL)
		fprintf(stderr, "%s: WARNING: already loaded module for "
			"vendor id %u, message type %u\n", __func__,
			mod->vendor.id, mod->msgtype.id);
	pbv->msgtypes[mod->msgtype.id] = mod;
}
