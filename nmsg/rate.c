/*
 * Copyright (c) 2008, 2009, 2012, 2013 by Farsight Security, Inc.
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

#include "libmy/my_rate.h"

/* Data structures. */

struct nmsg_rate {
	struct my_rate	*rate;
};

/* Export. */

nmsg_rate_t
nmsg_rate_init(unsigned rate_param, unsigned freq_param) {
	struct nmsg_rate *r;
	struct my_rate *rate;

	rate = my_rate_init(rate_param, freq_param);
	if (rate == NULL)
		return (NULL);

	r = calloc(1, sizeof(*r));
	if (r == NULL) {
		my_rate_destroy(&rate);
		return (NULL);
	}

	r->rate = rate;

	return (r);
}

void
nmsg_rate_destroy(nmsg_rate_t *r) {
	if (*r != NULL) {
		my_rate_destroy(&(*r)->rate);
		free(*r);
		*r = NULL;
	}
}

void
nmsg_rate_sleep(nmsg_rate_t r) {
	my_rate_sleep(r->rate);
}
