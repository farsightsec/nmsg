#include <stdio.h>

#include "my_config.h"
#include "list.h"
#include "my_alloc.h"

#define _EQUAL_DIV '='
#define _COLON_DIV ':'
#define _COMMENT '#'
#define _SECTION_BEGIN '['
#define _SECTION_END ']'

struct _my_config_item_value {
	char	*key;
	char	*value;
};

struct my_config_item {
	struct _my_config_item_value	*item;
	ISC_LINK(struct my_config_item)	link;
};

struct _my_config_section {
	char 					*name;
	size_t 					name_len;
	ISC_LIST(struct my_config_item)		items;
	ISC_LINK(struct _my_config_section)	link;
};

struct my_config {
	struct _my_config_section		*root;
	ISC_LIST(struct _my_config_section)	sections;
};

static const char *_my_strnchr(const char *data, size_t data_len, char ch);

static struct my_config_item *_my_config_find_item(struct my_config_item *items, const char *key, size_t key_len);

static void _my_config_set_item_value(struct _my_config_item_value *item, const char *key, size_t key_len,
				      const char *value, size_t value_len);

static struct my_config_item *_my_config_create_item(const char *key, size_t key_len,
						     const char *value, size_t value_len);

static struct _my_config_section *_my_config_add_section(struct my_config *config, bool root,
							 const char *name, size_t name_len);

static struct _my_config_section *_my_config_find_section(struct my_config *config, const char *name, size_t name_len);

static void _my_config_destroy_item(struct my_config_item *item);

static void _my_config_destroy_items(struct _my_config_section *section);

static void _my_config_destroy_sections(struct my_config *config);

/*
 * PRIVATE FUNCTIONS
 */

static const char *
_my_strnchr(const char *data, size_t data_len, char ch) {
	while(data_len > 0) {
		if (*data == ch)
			return data;
		--data_len;
		++data;
	}

	return NULL;
}

static struct my_config_item *
_my_config_find_item(struct my_config_item *items, const char *key, size_t key_len) {
	while(items != NULL) {
		if (strncmp(items->item->key, key, key_len) == 0)
			return items;
		items = ISC_LIST_NEXT(items, link);
	}
	return NULL;
}

static void
_my_config_set_item_value(struct _my_config_item_value *item, const char *key, size_t key_len, const char *value, size_t value_len) {
	my_free(item->key);
	my_free(item->value);
	item->key = my_strndup(key, key_len);
	item->value = my_strndup(value, value_len);
}

static struct my_config_item *
_my_config_create_item(const char *key, size_t key_len, const char *value, size_t value_len) {
	struct my_config_item *item;
	item = my_calloc(1, sizeof(struct my_config_item));
	item->item = my_calloc(1, sizeof(struct _my_config_item_value));
	_my_config_set_item_value(item->item, key, key_len, value, value_len);
	return item;
}

static bool
_my_config_add_item(struct _my_config_section *section, const char *data, size_t data_len) {
	size_t key_len = 0;
	size_t value_len = 0;
	const char *divider;
	struct my_config_item *item;

	divider = _my_strnchr(data, data_len, _EQUAL_DIV);
	if (divider == NULL)
		return false;

	key_len = divider - data;
	++divider;
	value_len = data_len - key_len - 1;

	while((data[key_len - 1] == ' ' || data[key_len - 1] == '\t') && key_len > 1)
		--key_len;

	while((*divider == ' ' || *divider == '\t') && value_len > 0) {
		++divider;
		--value_len;
	}

	if (value_len == 0)
		return false;

	while((divider[value_len - 1] == ' ' || divider[value_len - 1] == ' ') && value_len > 1)
		--value_len;

	if (key_len == 0 || value_len == 0)
		return false;

	item = _my_config_find_item(ISC_LIST_HEAD(section->items), data, key_len);

	if (item == NULL) {
		item = _my_config_create_item(data, key_len, divider, value_len);
		ISC_LIST_APPEND(section->items, item, link);
	} else {
		_my_config_set_item_value(item->item, data, key_len, divider, value_len);
	}

	return true;
}

static struct _my_config_section *
_my_config_add_section(struct my_config *config, bool root, const char *name, size_t name_len) {
	struct _my_config_section *section = my_calloc(1, sizeof(struct _my_config_section));

	section->name = my_strndup(name, name_len);
	section->name_len = name_len;
	ISC_LIST_INIT(section->items);

	if (root)
		config->root = section;
	else
		ISC_LIST_APPEND(config->sections, section, link);

	return section;
}

static struct _my_config_section *
_my_config_find_section(struct my_config *config, const char *name, size_t name_len) {
	struct _my_config_section *section;

	if (config->root != NULL) {
		name_len = (config->root->name_len < name_len ? config->root->name_len : name_len);
		if (strncmp(config->root->name, name, name_len) == 0)
			return config->root;
	}
	section = ISC_LIST_HEAD(config->sections);
	while(section != NULL) {
		name_len = (section->name_len < name_len ? section->name_len : name_len);

		if (strncmp(section->name, name, name_len) == 0)
			break;
		section = ISC_LIST_NEXT(section, link);
	}

	return section;
}

static void
_my_config_destroy_item(struct my_config_item *item) {
	my_free(item->item->key);
	my_free(item->item->value);
	my_free(item->item);
}

static void
_my_config_destroy_items(struct _my_config_section *section) {
	struct my_config_item *items;
	items = ISC_LIST_HEAD(section->items);

	while(items != NULL) {
		struct my_config_item *next;
		next = ISC_LIST_NEXT(items, link);
		_my_config_destroy_item(items);
		ISC_LIST_UNLINK(section->items, items, link);
		my_free(items);
		items = next;
	}
}

static void
_my_config_destroy_sections(struct my_config *config) {
	struct _my_config_section *sections;

	if (config->root != NULL) {
		_my_config_destroy_items(config->root);
		my_free(config->root->name);
		my_free(config->root);
	}

	sections = ISC_LIST_HEAD(config->sections);

	while(sections != NULL) {
		struct _my_config_section *next;
		next = ISC_LIST_NEXT(sections, link);
		my_free(sections->name);
		_my_config_destroy_items(sections);
		ISC_LIST_UNLINK(config->sections, sections, link);
		my_free(sections);
		sections = next;
	}
}

/*
 * PUBLIC FUNCTIONS
 */

struct my_config *
my_config_init(void) {
	struct my_config *result;
	result = my_calloc(1, sizeof(struct my_config));

	ISC_LIST_INIT(result->sections);

	return result;
}

bool
my_config_fill(struct my_config *config, const char *data) {
	const char *divider = NULL;
	struct _my_config_section *section = NULL;
	size_t data_len;

	if (config == NULL || data == NULL || *data == '\0')
		return false;

	section = _my_config_find_section(config, MY_CONFIG_DEFAULT_SECTION, sizeof(MY_CONFIG_DEFAULT_SECTION));
	if (section == NULL)
		section = _my_config_add_section(config, true, MY_CONFIG_DEFAULT_SECTION, sizeof(MY_CONFIG_DEFAULT_SECTION));

	for(;;) {
		divider = strchr(data, _COLON_DIV);
		data_len = (divider != NULL ? (size_t) (divider - data) : strlen(data));
		if (data_len == 0)
			break;
		if (!_my_config_add_item(section, data, data_len))
			return false;
		if (divider == NULL)
			break;
		data += data_len + 1;
	}

	return true;
}

bool
my_config_load(struct my_config *config, const char *filename) {
	bool result = false;
	char buffer[1024];
	FILE *f;
	struct _my_config_section *section = NULL;

	if (config == NULL || filename == NULL)
		return false;

	f = fopen(filename, "r");
	if (f == NULL)
		return false;

	while(fgets(buffer, sizeof(buffer), f)) {
		size_t line_len;
		char *ptr = buffer;

		while(*ptr == ' ' || *ptr == '\t')
			++ptr;

		if (*ptr == _COMMENT || *ptr == '\0' || *ptr == '\n')
			continue;

		line_len = strlen(ptr);
		if (line_len > 0 && ptr[line_len - 1] == '\n') /* Remove trailing \n */
			--line_len;

		if (line_len < 3) /* section and key value par minimum length is 3 ( [-] and a=b ) */
			goto out;

		if (*ptr == _SECTION_BEGIN) {
			if (ptr[line_len - 1] != _SECTION_END)
				goto out;

			++ptr;
			line_len -= 2;

			section = _my_config_find_section(config, ptr, line_len);
			if (section == NULL) {
				size_t tmp = (sizeof(MY_CONFIG_DEFAULT_SECTION) > line_len ? line_len : sizeof(MY_CONFIG_DEFAULT_SECTION));
				section = _my_config_add_section(config, strncmp(ptr, MY_CONFIG_DEFAULT_SECTION, tmp) == 0, ptr, line_len);
			}

			continue;
		}

		if (section == NULL)
			goto out;

		if (!_my_config_add_item(section, ptr, line_len))
			goto out;
	}

	/* Empty configuration file is failure */
	result = (config->root != NULL || !ISC_LIST_EMPTY(config->sections));
out:
	fclose(f);
	return result;
}

const struct my_config_item *
my_config_find_section(struct my_config *config, const char *name) {
	struct _my_config_section *section = NULL;

	if (config == NULL || name == NULL || (config->root == NULL && ISC_LIST_EMPTY(config->sections)))
		return NULL;

	section = _my_config_find_section(config, name, strlen(name));

	if (section == NULL)
		return NULL;

	return ISC_LIST_HEAD(section->items);
}

const struct my_config_item *
my_config_next_item(const struct my_config_item *item) {
	if (item == NULL)
		return NULL;

	return ISC_LIST_NEXT(item, link);
}

const char *
my_config_item_key(const struct my_config_item *item) {
	if (item == NULL || item->item == NULL)
		return NULL;

	return item->item->key;
}

const char *
my_config_item_value(const struct my_config_item *item) {
	if (item == NULL || item->item == NULL)
		return NULL;

	return item->item->value;
}

void
my_config_destroy(struct my_config **config) {
	if (config == NULL || *config == NULL)
		return;
	_my_config_destroy_sections(*config);
	my_free(*config);
}
