/*
 * Copyright (c) 2009, 2012 by Farsight Security, Inc.
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

#include "private.h"

/* Macros. */

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
						 sizeof(**alias) * num_aliases);
				(*alias)[num_aliases - 1] = strdup(tmp);
			}
		}
	}

	fclose(fp);

	/* append NULL sentinel */
	*alias = realloc(*alias, sizeof(**alias) * (num_aliases + 1));
	(*alias)[num_aliases] = NULL;

	return (num_aliases);
}

void
nmsg_chalias_free(char ***alias) {
	if (*alias == NULL)
		return;
	for (char **a = *alias; *a != NULL; a++)
		free(*a);
	free(*alias);
	*alias = NULL;
}
