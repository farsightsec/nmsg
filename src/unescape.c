/*
 * Copyright (c) 2009 by Farsight Security, Inc.
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

#include <stdlib.h>
#include <string.h>

#include "nmsgtool.h"

char *
unescape(const char *str) {
	bool escape;
	char *res;
	size_t len;
	size_t i, j;

	escape = false;
	len = strlen(str) + 1;
	res = malloc(len);
	if (res == NULL)
		return (NULL);

	for (i = 0, j = 0; i < len; i++) {
		char c = str[i];

		if (escape == true) {
			switch (c) {
			case 'n':
				res[j] = '\n';
				break;
			case 't':
				res[j] = '\t';
				break;
			case '\\':
				res[j] = '\\';
				break;
			}
			escape = false;
		} else {
			if (c == '\\') {
				escape = true;
				continue;
			}
			res[j] = c;
		}
		j++;
	}

	return (res);
}
