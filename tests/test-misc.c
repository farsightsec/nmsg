/*
 * Copyright (c) 2018 by Farsight Security, Inc.
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
#include <stdarg.h>

#include "nmsg/asprintf.h"

#define NAME	"test-misc"

#define TEST_FMT(buf, nexpect, fmt, ...)	{	\
							int _res;	\
							_res = nmsg_asprintf(buf, fmt, __VA_ARGS__);	\
							assert_buf(buf, _res, nexpect);	\
							_res = test_vasprintf(buf, fmt, __VA_ARGS__);	\
							assert_buf(buf, _res, nexpect);	\
						}


static int
test_vasprintf(char **strp, const char *fmt, ...)
{
	va_list ap;
	int res;

	va_start(ap, fmt);
	res = nmsg_vasprintf(strp, fmt, ap);
	va_end(ap);

	return res;
}

static void
assert_buf(char **buf, int bsize, int expected)
{
	assert(bsize == expected);
	assert(*buf != NULL);
	free(*buf);
	*buf = NULL;
}

static int
test_printf(void)
{
	char *pbuf = NULL;

	TEST_FMT(&pbuf, 11, "testing 123", NULL);
	TEST_FMT(&pbuf, 12, "testing %d", 1234);
	TEST_FMT(&pbuf, 15, "testing %.7d", 1234);
	TEST_FMT(&pbuf, 12, "Hello, %s", "world");
	
	return 0;
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

	ret |= check(test_printf(), "test-misc");

	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
