/* nmsg_mod.c - module support */

/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsg.h"
#include "nmsg_private.h"

/* Forward. */

static struct nmsg_dlmod *load_module(const char *path);
static void free_module(struct nmsg_dlmod **);
static void resize_pbmods_array(nmsg_pbmodset, unsigned vid, unsigned msgtype);
static unsigned idname_maxid(struct nmsg_idname *idnames);

/* Export. */

nmsg_pbmodset
nmsg_pbmodset_load(const char *path) {
	DIR *dir;
	char *oldwd;
	nmsg_pbmodset pbmodset;
	struct dirent *de;
	struct nmsg_dlmod *dlmod;
	struct nmsg_pbmod *pbmod;
	struct stat statbuf;

	pbmodset = calloc(1, sizeof(*pbmodset));
	assert(pbmodset != NULL);

	oldwd = getcwd(NULL, 0);
	if (oldwd == NULL) {
		free(pbmodset);
		return (NULL);
	}
	if (chdir(path) != 0) {
		free(pbmodset);
		free(oldwd);
		return (NULL);
	}

	dir = opendir(path);
	if (dir == NULL) {
		free(pbmodset);
		free(oldwd);
		return (NULL);
	}
	while ((de = readdir(dir)) != NULL) {
		char *fn;
		size_t fnlen;
		struct nmsg_idname *idname;
		unsigned maxid;

		if (stat(de->d_name, &statbuf) == -1)
			continue;
		if (!S_ISREG(statbuf.st_mode))
			continue;
		fn = de->d_name;
		fnlen = strlen(fn);
		if (!(fn[fnlen - 3] == '.' &&
		      fn[fnlen - 2] == 's' &&
		      fn[fnlen - 1] == 'o'))
			continue;
		dlmod = load_module(fn);
		if (dlmod == NULL) {
			perror("load_module");
			free(pbmodset);
			free(oldwd);
			closedir(dir);
			return (NULL);
		}
		pbmod = (struct nmsg_pbmod *)
			dlsym(dlmod->handle, "nmsg_pbmod_ctx");
		if (pbmod == NULL ||
		    pbmod->pbmver != NMSG_PBMOD_VERSION)
		{
			printf("not loading %s\n", fn);
			free_module(&dlmod);
			continue;
		}
		if (pbmod->init)
			pbmod->init();
		maxid = idname_maxid(pbmod->msgtype);
		resize_pbmods_array(pbmodset, pbmod->vendor.id, maxid);
		for (idname = pbmod->msgtype; idname->name != NULL; idname++)
			pbmodset->vendors[pbmod->vendor.id]->v_pbmods[idname->id] = pbmod;
		ISC_LIST_APPEND(pbmodset->dlmods, dlmod, link);
		printf("loaded module %s\n", fn);
	}
	if (chdir(oldwd) != 0) {
		free(pbmodset);
		free(oldwd);
		closedir(dir);
		return (NULL);
	}
	free(oldwd);
	closedir(dir);

	return (pbmodset);
}

void
nmsg_pbmodset_destroy(nmsg_pbmodset *pms) {
	struct nmsg_dlmod *dlmod, *dlmod_next;
	nmsg_pbmodset ms;
	unsigned i;

	ms = *pms;
	dlmod = ISC_LIST_HEAD(ms->dlmods);
	while (dlmod != NULL) {
		dlmod_next = ISC_LIST_NEXT(dlmod, link);
		free_module(&dlmod);
		dlmod = dlmod_next;
	}
	for (i = 0; i <= ms->nv; i++) {
		struct nmsg_vid_msgtype *v;
		v = ms->vendors[i];

		if (v != NULL) {
			free(v->v_pbmods);
			free(v);
		}
	}
	free(ms->vendors);
	free(ms);
	*pms = NULL;
}

unsigned
nmsg_vname2vid(nmsg_pbmodset ms, const char *vname) {
	unsigned i, j;

	for (i = 0; i <= ms->nv; i++) {
		struct nmsg_vid_msgtype *v;
		v = ms->vendors[i];

		if (v != NULL && v->nm > 0) {
			for (j = 0; j <= v->nm; j++) {
				struct nmsg_pbmod *mod;
				mod = v->v_pbmods[j];

				if (mod != NULL &&
				    strcasecmp(mod->vendor.name, vname) == 0)
					return (mod->vendor.id);
			}
		}
	}
	return (0);
}

unsigned
nmsg_mname2msgtype(nmsg_pbmodset ms, unsigned vid, const char *mname) {
	unsigned i;

	if (vid <= ms->nv) {
		struct nmsg_vid_msgtype *v;

		v = ms->vendors[vid];
		if (v == NULL)
			return (0);
		for (i = 0; i <= v->nm; i++) {
			struct nmsg_pbmod *mod;
			struct nmsg_idname *idnames;

			mod = v->v_pbmods[i];
			if (mod != NULL) {
				idnames = mod->msgtype;
				for (; idnames->name != NULL; idnames++) {
					if (strcasecmp(idnames->name, mname) == 0)
						return (idnames->id);
				}
			}
		}
	}

	return (0);
}

/* Private. */

static unsigned
idname_maxid(struct nmsg_idname *idnames) {
	unsigned max;

	for (max = 0; idnames->name != NULL; idnames++) {
		if (idnames->id > max)
			max = idnames->id;
	}

	return (max);
}

static struct nmsg_dlmod *
load_module(const char *path) {
	char *relpath;
	struct nmsg_dlmod *dlmod;

	dlmod = calloc(1, sizeof(*dlmod));
	assert(dlmod != NULL);
	ISC_LINK_INIT(dlmod, link);
	dlmod->path = strdup(path);

	relpath = calloc(1, strlen(path) + 3);
	relpath[0] = '.';
	relpath[1] = '/';
	strcpy(relpath + 2, path);

	dlmod->handle = dlopen(relpath, RTLD_NOW);
	free(relpath);
	if (dlmod->handle == NULL) {
		fprintf(stderr, "%s\n", dlerror());
		free(dlmod);
		return (NULL);
	}
	return (dlmod);
}

static void
free_module(struct nmsg_dlmod **dlmod) {
	printf("unloading module %s\n", (*dlmod)->path);
	dlclose((*dlmod)->handle);
	free((*dlmod)->path);
	free(*dlmod);
	*dlmod = NULL;
}

static void
resize_pbmods_array(nmsg_pbmodset ms, unsigned vid, unsigned msgtype) {
	struct nmsg_vid_msgtype *vm;
	unsigned i;

	if (vid > ms->nv) {
		ms->vendors = realloc(ms->vendors, sizeof(void *) * (vid + 1));
		assert(ms->vendors != NULL);
		for (i = ms->nv; i < vid; i++)
			ms->vendors[i] = NULL;
		vm = ms->vendors[vid] = calloc(1, sizeof(*vm));
		assert(vm != NULL);
		ms->nv = vid;
	}

	vm = ms->vendors[vid];
	if (msgtype > vm->nm) {
		vm->v_pbmods = realloc(vm->v_pbmods,
				sizeof(void *) * (msgtype + 1));
		assert(vm->v_pbmods != NULL);
		for (i = vm->nm; i < msgtype; i++)
			vm->v_pbmods[msgtype] = NULL;
		vm->nm = msgtype;
	}
}
