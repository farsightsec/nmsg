/* nmsg_dlmod - dlopen(3) wrapper */

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

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nmsg.h"
#include "private.h"

/* Export. */

struct nmsg_dlmod *
nmsg_dlmod_open(const char *path) {
	char *relpath;
	struct nmsg_dlmod *dlmod;

	dlmod = calloc(1, sizeof(*dlmod));
	assert(dlmod != NULL);
	ISC_LINK_INIT(dlmod, link);
	dlmod->path = strdup(path);
	assert(dlmod->path != NULL);

	relpath = calloc(1, strlen(path) + 3);
	assert(relpath != NULL);
	relpath[0] = '.';
	relpath[1] = '/';
	strcpy(relpath + 2, path);

	dlmod->handle = dlopen(relpath, RTLD_NOW);
	free(relpath);
	if (dlmod->handle == NULL) {
		fprintf(stderr, "%s: %s\n", __func__, dlerror());
		free(dlmod);
		return (NULL);
	}
	(void) dlerror();
	return (dlmod);
}

void
nmsg_dlmod_destroy(struct nmsg_dlmod **dlmod) {
	dlclose((*dlmod)->handle);
	free((*dlmod)->path);
	free(*dlmod);
	*dlmod = NULL;
}
