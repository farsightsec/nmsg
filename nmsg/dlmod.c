/*
 * Copyright (c) 2008, 2009, 2012 by Farsight Security, Inc.
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

/* Internal functions. */

struct nmsg_dlmod *
_nmsg_dlmod_init(const char *path) {
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

	dlmod->handle = dlopen(relpath, RTLD_LAZY);
	free(relpath);
	if (dlmod->handle == NULL) {
		fprintf(stderr, "%s: %s\n", __func__, dlerror());
		free(dlmod);
		return (NULL);
	}
	return (dlmod);
}

void
_nmsg_dlmod_destroy(struct nmsg_dlmod **dlmod) {
	if (dlclose((*dlmod)->handle) != 0)
		fprintf(stderr, "%s: %s\n", __func__, dlerror());
	free((*dlmod)->path);
	free(*dlmod);
	*dlmod = NULL;
}
