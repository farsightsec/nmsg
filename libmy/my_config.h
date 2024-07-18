#ifndef MY_CONFIG_H
#define MY_CONFIG_H

#include <stdbool.h>

#define MY_CONFIG_DEFAULT_SECTION "default"

struct my_config;
struct my_config_item;

struct my_config * my_config_init(void);

bool my_config_fill(struct my_config *, const char *);
bool my_config_load(struct my_config *, const char *);

const struct my_config_item * my_config_find_section(struct my_config *, const char *);
const struct my_config_item * my_config_next_item(const struct my_config_item *);

const char * my_config_item_key(const struct my_config_item *);
const char * my_config_item_value(const struct my_config_item *);

void my_config_destroy(struct my_config **);

#endif //NMSG_MY_CONFIG_H
