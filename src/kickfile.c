/* kickfile */

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

#include "nmsg_port.h"

#include <sys/time.h>
#include <sys/types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nmsg.h>
#include "config.h"

#include "kickfile.h"

/* Export. */

char *
kickfile_time(void) {
	char *kt;
	char when[32];
	struct timespec ts;
	struct tm *tm;
	time_t t;

	nmsg_time_get(&ts);
	t = (time_t) ts.tv_sec;
	tm = gmtime(&t);
	strftime(when, sizeof(when), "%Y%m%d.%H%M.%s", tm);
	asprintf(&kt, "%s.%09lu", when, ts.tv_nsec);
	assert(kt != NULL);

	return (kt);
}

void
kickfile_destroy(struct kickfile **kf) {
	free((*kf)->basename);
	free((*kf)->curname);
	free((*kf)->tmpname);
	free((*kf));
	*kf = NULL;
}

void
kickfile_docmd(struct kickfile *kf) {
	char *cmd;

	if (rename(kf->tmpname, kf->curname) < 0) {
		perror("rename");
		unlink(kf->tmpname);
	} else if (kf->cmd != NULL && *kf->cmd != '\0') {
		asprintf(&cmd, "%s %s &", kf->cmd, kf->curname);
		system(cmd);
		free(cmd);
	}
}

void
kickfile_rotate(struct kickfile *kf) {
	char *kt;

	free(kf->tmpname);
	free(kf->curname);
	kt = kickfile_time();
	asprintf(&kf->tmpname, "%s.%s.part", kf->basename, kt);
	asprintf(&kf->curname, "%s.%s", kf->basename, kt);
	free(kt);
}
