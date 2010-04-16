/*
 * Copyright (c) 2010 by Internet Systems Consortium, Inc. ("ISC")
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

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsgtool.h"

void
pidfile_create(const char *pidfile) {
	FILE *fp;
	pid_t pid;

	if (pidfile == NULL)
		return;

	pid = getpid();
	fp = fopen(pidfile, "w");
	if (fp == NULL) {
		fprintf(stderr, "unable to open pidfile %s: %s\n", pidfile,
			strerror(errno));
		return;
	}
	fprintf(fp, "%d\n", pid);
	fclose(fp);
}

bool
daemonize(void) {
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return (false);
	if (pid != 0)
		exit(0);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	setsid();

	if (chdir("/") != 0)
		return (false);

	return (true);
}
