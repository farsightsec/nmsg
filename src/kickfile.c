/*
 * Copyright (c) 2008-2016 by Farsight Security, Inc.
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

#ifdef HAVE_LIBGEN_H
# include <libgen.h>
#endif

#include <sys/time.h>
#include <sys/types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nmsg.h>

#include "kickfile.h"

/* Export. */

char *
kickfile_time(void) {
	char *kt;
	char when[32];
	struct timespec ts;
	struct tm tm;
	time_t t;

	nmsg_timespec_get(&ts);
	t = (time_t) ts.tv_sec;
	gmtime_r(&t, &tm);
	strftime(when, sizeof(when), "%Y%m%d.%H%M.%S", &tm);
	nmsg_asprintf(&kt, "%s.%09ld", when, ts.tv_nsec);
	assert(kt != NULL);

	return (kt);
}

void
kickfile_destroy(struct kickfile **kf) {
	free((*kf)->basename);
	free((*kf)->curname);
	free((*kf)->tmpname);
	free((*kf)->suffix);
	free((*kf));
	*kf = NULL;
}

void
kickfile_exec(struct kickfile *kf) {
	char *cmd;

	if (kf != NULL && kf->tmpname != NULL && kf->curname != NULL) {
		if (rename(kf->tmpname, kf->curname) < 0) {
			perror("rename");
			unlink(kf->tmpname);
		} else if (kf->cmd != NULL && *kf->cmd != '\0') {
			int rc;

			nmsg_asprintf(&cmd, "%s %s &", kf->cmd, kf->curname);
			rc = system(cmd);
			if (rc != 0)
				fprintf(stderr, "WARNING: system() failed\n");
			free(cmd);
		}
	}
}

void
kickfile_rotate(struct kickfile *kf) {
	char *kt;
	char *dup_for_basename, *s_basename;
	char *dup_for_dirname, *s_dirname;

	kt = kickfile_time();
	dup_for_basename = strdup(kf->basename);
	dup_for_dirname = strdup(kf->basename);
	s_basename = basename(dup_for_basename);
	s_dirname = dirname(dup_for_dirname);
	assert(s_basename != NULL);
	assert(s_dirname != NULL);

	free(kf->tmpname);
	free(kf->curname);
	nmsg_asprintf(&kf->tmpname, "%s/.%s.%s.part", s_dirname, s_basename, kt);
	nmsg_asprintf(&kf->curname, "%s/%s.%s%s", s_dirname, s_basename, kt,
		      kf->suffix != NULL ? kf->suffix : "");
	free(kt);
	free(dup_for_basename);
	free(dup_for_dirname);
}
