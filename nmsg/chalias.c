/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>

#include "private.h"

#define CHALIAS_FILE	NMSG_ETCDIR "/nmsg.chalias"
#define CHALIAS_FILE2	NMSG_ETCDIR "/nmsgtool.chalias"

#define MAX_LINE_SZ	1024

/* Functions. */

int
nmsg_chalias_lookup(const char *ch, char ***alias) {
	FILE *fp;
	char line[1024];
	char *saveptr, *tmp;
	int num_aliases;

	*alias = NULL;
	num_aliases = 0;

	fp = fopen(CHALIAS_FILE, "r");
	if (fp == NULL) {
		fp = fopen(CHALIAS_FILE2, "r");
		if (fp == NULL)
			return (-1);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		tmp = strtok_r(line, " \t", &saveptr);
		if (tmp != NULL && strcmp(tmp, ch) == 0) {
			while ((tmp = strtok_r(NULL, " \t\n", &saveptr))
			       != NULL)
			{
				num_aliases += 1;
				*alias = realloc(*alias,
						 sizeof(*alias) * num_aliases);
				(*alias)[num_aliases - 1] = strdup(tmp);
			}
		}
	}

	fclose(fp);

	/* append NULL sentinel */
	*alias = realloc(*alias, sizeof(*alias) * (num_aliases + 1));
	(*alias)[num_aliases] = NULL;

	return (num_aliases);
}

void
nmsg_chalias_free(char ***alias) {
	for (char **a = *alias; *a != NULL; a++)
		free(*a);
	free(*alias);
	*alias = NULL;
}
