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

#ifndef NMSG_CONFIG_FILE_H
#define NMSG_CONFIG_FILE_H

#include <stdbool.h>

/*
 * Provides support for "INI" style configuration file:
 * 	# This is a configuration file example
 * 	[Section1]
 * 	Key1 = Value1
 * 	Key2 = Value2
 */

#define CONFIG_FILE_DEFAULT_SECTION "default"

struct config_file;
struct config_file_item;

struct config_file *config_file_init(void);

bool config_file_fill(struct config_file *, const char *);
bool config_file_load(struct config_file *, const char *);

const struct config_file_item *config_file_find_section(struct config_file *, const char *);
const struct config_file_item *config_file_next_item(const struct config_file_item *);

const char *config_file_item_key(const struct config_file_item *);
const char *config_file_item_value(const struct config_file_item *);

void config_file_destroy(struct config_file **);

#endif /* NMSG_CONFIG_FILE_H */
