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

/* Export. */

nmsg_pbmodset
nmsg_pbmodset_load(const char *path) {
	DIR *dir;
	char *oldwd;
	struct dirent *de;
	struct stat statbuf;
	nmsg_pbmodset pbmodset;
	struct nmsg_pbmod *pbmod;
	struct nmsg_dlmod *dlmod;

	pbmodset = calloc(1, sizeof(*pbmodset));
	assert(pbmodset != NULL);

	oldwd = getcwd(NULL, 0);
	if (oldwd == NULL)
		return (NULL);
	if (chdir(path) != 0)
		return (NULL);

	dir = opendir(path);
	if (dir == NULL)
		return (NULL);
	while ((de = readdir(dir)) != NULL) {
		char *fn;
		size_t fnlen;

		if (stat(de->d_name, &statbuf) == -1)
			continue;
		if (!S_ISREG(statbuf.st_mode))
			continue;
		fn = de->d_name;
		fnlen = strlen(fn);
		if (fn[fnlen - 3] == '.' &&
		    fn[fnlen - 2] == 's' &&
		    fn[fnlen - 1] == 'o')
		{
			dlmod = load_module(fn);
			pbmod = (struct nmsg_pbmod *)
			        dlsym(dlmod->handle, "nmsg_pbmod_ctx");
			if (pbmod == NULL ||
			    pbmod->pbmver != NMSG_PBMOD_VERSION)
			{
				printf("not loading %s\n", fn);
				free_module(&dlmod);
				continue;
			}
			printf("loaded module %s\n", fn);
		}
	}
	if (chdir(oldwd) != 0)
		return (NULL);

	return (pbmodset);
}

void
nmsg_pbmodset_destroy(nmsg_pbmodset *pbmodset) {
	struct nmsg_dlmod *dlmod;

	for (dlmod = ISC_LIST_HEAD((*pbmodset)->dlmods);
	     dlmod != NULL;
	     dlmod = ISC_LIST_NEXT(dlmod, link))
	{
		free_module(&dlmod);
	}
	free(*pbmodset);
	*pbmodset = NULL;
}

/* Private. */

static struct nmsg_dlmod *
load_module(const char *path) {
	struct nmsg_dlmod *dlmod;

	dlmod = calloc(1, sizeof(*dlmod));
	assert(dlmod != NULL);
	ISC_LINK_INIT(dlmod, link);
	dlmod->path = path;

	dlmod->handle = dlopen(path, RTLD_NOW);
	if (dlmod->handle == NULL) {
		free(dlmod);
		return (NULL);
	}
	return (dlmod);
}

static void free_module(struct nmsg_dlmod **dlmod) {
	dlclose((*dlmod)->handle);
	free(*dlmod);
	*dlmod = NULL;
}
