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

#include <stdio.h>
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

	struct nmsg_fltmod_plugin p = {0};

	/* 's': sum up sizeof() for all the fields. */
	size_t s = 0;
	s += sizeof(p.fltmod_version);
	s += sizeof(p.module_init);
	s += sizeof(p.module_fini);
	s += sizeof(p.thread_init);
	s += sizeof(p.thread_fini);
	s += sizeof(p.filter_message);
	s += sizeof(p._reserved15);
	s += sizeof(p._reserved14);
	s += sizeof(p._reserved13);
	s += sizeof(p._reserved12);
	s += sizeof(p._reserved11);
	s += sizeof(p._reserved10);
	s += sizeof(p._reserved9);
	s += sizeof(p._reserved8);
	s += sizeof(p._reserved7);
	s += sizeof(p._reserved6);
	s += sizeof(p._reserved5);
	s += sizeof(p._reserved4);
	s += sizeof(p._reserved3);
	s += sizeof(p._reserved2);
	s += sizeof(p._reserved1);
	s += sizeof(p._reserved0);

	/* 't': sum up the sizes of what we think the fields are. */
	size_t t = 0;
	t += sizeof(long);
	t += 21 * sizeof(void *);

	/* Hopefully there are no holes in the struct. */
	if (s != t || s != sizeof(struct nmsg_fltmod_plugin)) {
		ret |= 1;
	}

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

	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
