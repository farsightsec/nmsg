/*
 * Copyright (c) 2024 DomainTools LLC
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

#define _EQUAL_DIV '='
#define _COLON_DIV ':'
#define _COMMENT '#'
#define _SECTION_BEGIN '['
#define _SECTION_END ']'

struct _config_file_item_value {
	char	*key;
	char	*value;
};

struct config_file_item {
	struct _config_file_item_value		*item;
	ISC_LINK(struct config_file_item)	link;
};

struct _config_file_section {
	char 					*name;
	ISC_LIST(struct config_file_item)	items;
	ISC_LINK(struct _config_file_section)	link;
};

struct config_file {
	struct _config_file_section		*root;
	ISC_LIST(struct _config_file_section)	sections;
};

static struct config_file_item *_config_file_find_item(struct config_file_item *items, const char *key);

static void _config_file_set_item_value(struct _config_file_item_value *item,
					const char *key, const char *value);

static struct config_file_item *_config_file_create_item(const char *key, const char *value);

static struct _config_file_section *_config_file_add_section(struct config_file *config, bool root, const char *name);

static struct _config_file_section *_config_file_find_section(struct config_file *config, const char *name);

static void _config_file_destroy_item(struct config_file_item *item);

static void _config_file_destroy_items(struct _config_file_section *section);

static void _config_file_destroy_sections(struct config_file *config);

/*
 * PRIVATE FUNCTIONS
 */

static struct config_file_item *
_config_file_find_item(struct config_file_item *items, const char *key)
{
	while (items != NULL) {
		if (strcmp(items->item->key, key) == 0)
			return items;
		items = ISC_LIST_NEXT(items, link);
	}
	return NULL;
}

static void
_config_file_set_item_value(struct _config_file_item_value *item,
			    const char *key, const char *value)
{
	my_free(item->key);
	my_free(item->value);
	item->key = my_strdup(key);
	item->value = my_strdup(value);
}

static struct config_file_item *
_config_file_create_item(const char *key, const char *value) {
	struct config_file_item *item;

	item = my_calloc(1, sizeof(struct config_file_item));
	item->item = my_calloc(1, sizeof(struct _config_file_item_value));
	_config_file_set_item_value(item->item, key, value);

	return item;
}

static bool
_config_file_add_item(struct _config_file_section *section, char *data) {
	char *key, *value;
	size_t key_len = 0, value_len = 0;
	char *divider;
	struct config_file_item *item;

	divider = strchr(data, _EQUAL_DIV);
	if (divider == NULL)
		return false;

	*divider = '\0';

	key = data;
	key_len = strlen(key);
	value = divider + 1;
	value_len = strlen(value);

	while ((key_len > 1) && isblank(key[key_len - 1]))
		--key_len;

	while (isblank(*value)) {
		++value;
		--value_len;
	}

	while ((value_len > 1) && isblank(value[value_len - 1]) )
		--value_len;

	if (key_len == 0 || value_len == 0)
		return false;

	key[key_len] = '\0';
	value[value_len] = '\0';

	item = _config_file_find_item(ISC_LIST_HEAD(section->items), key);
	if (item == NULL) {
		item = _config_file_create_item(key, value);
		ISC_LIST_APPEND(section->items, item, link);
	} else
		_config_file_set_item_value(item->item, key, value);

	return true;
}

static struct _config_file_section *
_config_file_add_section(struct config_file *config, bool root, const char *name) {
	struct _config_file_section *section;

	section = my_calloc(1, sizeof(struct _config_file_section));
	section->name = my_strdup(name);
	ISC_LIST_INIT(section->items);

	if (root)
		config->root = section;
	else
		ISC_LIST_APPEND(config->sections, section, link);

	return section;
}

static struct _config_file_section *
_config_file_find_section(struct config_file *config, const char *name) {
	struct _config_file_section *section;

	if (config->root != NULL && !strcmp(config->root->name, name))
		return config->root;

	section = ISC_LIST_HEAD(config->sections);
	while (section != NULL) {
		if (!strcmp(section->name, name))
			break;
		section = ISC_LIST_NEXT(section, link);
	}

	return section;
}

static void
_config_file_destroy_item(struct config_file_item *item) {
	my_free(item->item->key);
	my_free(item->item->value);
	my_free(item->item);
}

static void
_config_file_destroy_items(struct _config_file_section *section) {
	struct config_file_item *items = ISC_LIST_HEAD(section->items);

	while (items != NULL) {
		struct config_file_item *next;

		next = ISC_LIST_NEXT(items, link);
		_config_file_destroy_item(items);
		ISC_LIST_UNLINK(section->items, items, link);
		my_free(items);
		items = next;
	}
}

static void
_config_file_destroy_sections(struct config_file *config) {
	struct _config_file_section *sections;

	if (config->root != NULL) {
		_config_file_destroy_items(config->root);
		my_free(config->root->name);
		my_free(config->root);
	}

	sections = ISC_LIST_HEAD(config->sections);
	while (sections != NULL) {
		struct _config_file_section *next;

		next = ISC_LIST_NEXT(sections, link);
		my_free(sections->name);
		_config_file_destroy_items(sections);
		ISC_LIST_UNLINK(config->sections, sections, link);
		my_free(sections);
		sections = next;
	}
}

/*
 * PUBLIC FUNCTIONS
 */

struct config_file *
config_file_init(void) {
	struct config_file *result;

	result = my_calloc(1, sizeof(struct config_file));
	ISC_LIST_INIT(result->sections);

	return result;
}

/* Load a variable number of key=val options from a configuration string. */
bool
config_file_fill_from_str(struct config_file *config, const char *data) {
	struct _config_file_section *section = NULL;
	char *dcopy, *dptr;

	if (config == NULL || data == NULL || *data == '\0')
		return false;

	dptr = dcopy = my_strdup(data);

	section = _config_file_find_section(config, CONFIG_FILE_DEFAULT_SECTION);
	if (section == NULL)
		section = _config_file_add_section(config, true, CONFIG_FILE_DEFAULT_SECTION);

	while (*dptr != '\0') {
		char *divider = strchr(dptr, _COLON_DIV);

		if (divider != NULL)
			*divider = '\0';
		if (!_config_file_add_item(section, dptr)) {
			free(dcopy);
			return false;
		}

		if (divider == NULL)
			break;
		dptr = divider + 1;
	}

	free(dcopy);
	return true;
}

/* Load options from INI-style configuration file. */
bool
config_file_load(struct config_file *config, const char *filename) {
	bool result = false;
	char buffer[1024] = {0};
	FILE *f;
	struct _config_file_section *section = NULL;

	if (config == NULL || filename == NULL)
		return false;

	f = fopen(filename, "r");
	if (f == NULL)
		return false;

	while (fgets(buffer, sizeof(buffer) - 1, f)) {
		size_t line_len;
		char *ptr = buffer;

		while (isblank(*ptr))
			++ptr;

		if (*ptr == _COMMENT || *ptr == '\0' || *ptr == '\n')
			continue;

		line_len = strlen(ptr);
		/* Remove trailing \n or blank */
		while (line_len > 1 && (isblank(ptr[line_len - 1]) || ptr[line_len - 1] == '\n'))
			--line_len;

		if (line_len < 3) /* section and key value par minimum length is 3 ( [-] and a=b ) */
			goto out;

		if (*ptr == _SECTION_BEGIN) {
			if (ptr[line_len - 1] != _SECTION_END)
				goto out;

			ptr[line_len - 1] = '\0';
			++ptr;

			section = _config_file_find_section(config, ptr);
			/* Set the current section to the new section. */
			if (section == NULL) {
				bool is_root = (strcmp(ptr, CONFIG_FILE_DEFAULT_SECTION) == 0);
				section = _config_file_add_section(config, is_root, ptr);
			}

			continue;
		}

		if (section == NULL)
			goto out;

		ptr[line_len] = '\0';
		if (!_config_file_add_item(section, ptr))
			goto out;
	}

	/* Empty configuration file is failure */
	result = (config->root != NULL || !ISC_LIST_EMPTY(config->sections));
out:
	fclose(f);
	return result;
}

const struct config_file_item *
config_file_find_section(struct config_file *config, const char *name) {
	struct _config_file_section *section = NULL;

	if (config == NULL || name == NULL)
		return NULL;

	section = _config_file_find_section(config, name);
	if (section == NULL)
		return NULL;

	return ISC_LIST_HEAD(section->items);
}

const struct config_file_item *
config_file_next_item(const struct config_file_item *item) {
	if (item == NULL)
		return NULL;

	return ISC_LIST_NEXT(item, link);
}

const char *
config_file_item_key(const struct config_file_item *item) {
	if (item == NULL || item->item == NULL)
		return NULL;

	return item->item->key;
}

const char *
config_file_item_value(const struct config_file_item *item) {
	if (item == NULL || item->item == NULL)
		return NULL;

	return item->item->value;
}

void
config_file_destroy(struct config_file **config) {
	if (config == NULL || *config == NULL)
		return;

	_config_file_destroy_sections(*config);
	my_free(*config);
}
