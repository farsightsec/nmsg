/*
 * Copyright (c) 2010 by Farsight Security, Inc.
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

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nmsgtool.h"

FILE *
pidfile_open(const char *pidfile) {
	FILE *fp;

	if (pidfile == NULL)
		return (NULL);

	fp = fopen(pidfile, "w");
	if (fp == NULL) {
		fprintf(stderr, "unable to open pidfile %s: %s\n", pidfile,
			strerror(errno));
		return (NULL);
	}

	return (fp);
}

void
pidfile_write(FILE *fp) {
	pid_t pid;

	if (fp == NULL)
		return;

	pid = getpid();
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
