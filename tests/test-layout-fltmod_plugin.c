/*
 * Copyright (c) 2016 by Farsight Security, Inc.
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

#include <assert.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>

#include "nmsg/fltmod_plugin.h"

#define NAME	"test-layout_fltmod_plugin"

/**
 * These tests are inherently compiler and architecture specific, but hopefully
 * will catch inadvertent ABI-breaking changes to 'struct fltmod_plugin'.
 */

static int
test_sizeof(void)
{
	int ret = 0;

	/* This tests that the overall size of the structure hasn't changed. */
	size_t t = 0;
	t += sizeof(long);
	t += 21 * sizeof(void *);
	if (t != sizeof(struct nmsg_fltmod_plugin)) {
		ret |= 1;
	}

	return ret;
}

static int
test_offsetof(void)
{
	int ret = 0;

	/**
	 * These assert()'s test for both the existence of the non-reserved
	 * fields in the structure, as well as their ordering within the
	 * structure.
	 */
	size_t offset = 0;
	assert(offset == offsetof(struct nmsg_fltmod_plugin, fltmod_version));

	offset += sizeof(long);
	assert(offset == offsetof(struct nmsg_fltmod_plugin, module_init));

	offset += sizeof(void *);
	assert(offset == offsetof(struct nmsg_fltmod_plugin, module_fini));

	offset += sizeof(void *);
	assert(offset == offsetof(struct nmsg_fltmod_plugin, thread_init));

	offset += sizeof(void *);
	assert(offset == offsetof(struct nmsg_fltmod_plugin, thread_fini));

	offset += sizeof(void *);
	assert(offset == offsetof(struct nmsg_fltmod_plugin, filter_message));

	return ret;
}

static int
check(int ret, const char *s)
{
	if (ret == 0) {
		fprintf(stderr, NAME ": PASS: %s\n", s);
	} else {
		fprintf(stderr, NAME ": FAIL: %s\n", s);
	}
	return ret;
}

int
main(void)
{
	int ret = 0;

	ret |= check(test_sizeof(), "test-sizeof");
	ret |= check(test_offsetof(), "test-offsetof");

	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
