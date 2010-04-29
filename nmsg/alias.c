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

#include "nmsg_port.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <nmsg.h>

#include "private.h"

#define ALIAS_FILE_OPERATOR	NMSG_ETCDIR "/nmsg.opalias"
#define ALIAS_FILE_GROUP	NMSG_ETCDIR "/nmsg.gralias"

#define ALIAS_SZ_INIT		16
#define MAX_LINE_SZ		1024

struct nmsg_alias {
	size_t max_idx;
	char **value;
};

static int nmsg_alias_initialized = 0;
static struct nmsg_alias alias_operator;
static struct nmsg_alias alias_group;

/* Forward. */

static nmsg_res alias_init(struct nmsg_alias *, const char *fname);
static nmsg_res alias_resize(struct nmsg_alias *, unsigned n); 
static void alias_free(struct nmsg_alias *); 

/* Functions. */

const char *
nmsg_alias_by_key(nmsg_alias_e ae, unsigned key) {
	struct nmsg_alias *al = NULL;

	if (ae == nmsg_alias_operator)
		al = &alias_operator;
	else if (ae == nmsg_alias_group)
		al = &alias_group;

	assert(al != NULL);

	if (key <= al->max_idx)
		return (al->value[key]);

	return (NULL);
}

unsigned
nmsg_alias_by_value(nmsg_alias_e ae, const char *value) {
	struct nmsg_alias *al = NULL;

	if (ae == nmsg_alias_operator)
		al = &alias_operator;
	else if (ae == nmsg_alias_group)
		al = &alias_group;

	assert(al != NULL);

	for (unsigned i = 0; i <= al->max_idx; i++)
		if (al->value[i] != NULL &&
		    strcasecmp(value, al->value[i]) == 0)
			return (i);

	return (0);
}

nmsg_res
_nmsg_alias_init(void) {
	nmsg_res res;

	if (nmsg_alias_initialized == 0) {
		res = alias_init(&alias_operator, ALIAS_FILE_OPERATOR);
		if (res != nmsg_res_success)
			return (res);

		res = alias_init(&alias_group, ALIAS_FILE_GROUP);
		if (res != nmsg_res_success)
			return (res);

		nmsg_alias_initialized = 1;
	}

	return (nmsg_res_success);
}

void
_nmsg_alias_fini(void) {
	if (nmsg_alias_initialized == 1) {
		alias_free(&alias_operator);
		alias_free(&alias_group);
		nmsg_alias_initialized = 0;
	}
}

/* Private. */

static nmsg_res
alias_init(struct nmsg_alias *al, const char *fname) {
	FILE *fp;
	char line[MAX_LINE_SZ];
	char *saveptr, *str_key, *str_value;
	char *t;
	unsigned key;
	nmsg_res res;

	res = nmsg_res_success;

	al->value = malloc(sizeof(*(al->value)) * (ALIAS_SZ_INIT + 1));
	if (al->value == NULL)
		return (nmsg_res_failure);
	al->max_idx = ALIAS_SZ_INIT;
	for (unsigned i = 0; i <= al->max_idx; i++)
		al->value[i] = NULL;

	fp = fopen(fname, "r");
	if (fp == NULL)
		/* file may not exist */
		return (nmsg_res_success);

	while (fgets(line, sizeof(line), fp) != NULL) {
		str_key = strtok_r(line, " \t", &saveptr);
		str_value = strtok_r(NULL, " \t\n", &saveptr);
		if (str_key == NULL || str_value == NULL) {
			res = nmsg_res_failure;
			break;
		}

		key = (unsigned) strtoul(str_key, &t, 0);
		if (*t != '\0') {
			res = nmsg_res_failure;
			break;
		}

		if (key > al->max_idx) {
			if (alias_resize(al, key) != nmsg_res_success) {
				res = nmsg_res_failure;
				break;
			}
		}

		al->value[key] = strdup(str_value);
	}

	fclose(fp);
	return (res);
}

static nmsg_res
alias_resize(struct nmsg_alias *al, unsigned n) {
	unsigned max_idx;
	void *tmp;

	n += 1;

	if (n > al->max_idx) {
		max_idx = al->max_idx * 2;
		if (n > max_idx)
			max_idx = n + 1;

		tmp = al->value;
		al->value = realloc(al->value, (max_idx + 1) * sizeof(*(al->value)));
		if (al->value == NULL) {
			free(tmp);
			al->max_idx = 0;
			return (nmsg_res_failure);
		}
		for (unsigned i = al->max_idx + 1; i <= max_idx; i++)
			al->value[i] = NULL;
		al->max_idx = max_idx;
	}
	return (nmsg_res_success);
}

static void
alias_free(struct nmsg_alias *al) {
	for (unsigned i = 0; i <= al->max_idx; i++)
		if (al->value[i] != NULL)
			free(al->value[i]);
	free(al->value);
	al->value = NULL;
	al->max_idx = 0;
}
