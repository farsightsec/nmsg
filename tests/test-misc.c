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
#include <string.h>
#include <stdarg.h>

#include "nmsg.h"
#include "nmsg/asprintf.h"
#include "nmsg/alias.h"
#include "nmsg/chalias.h"
#include "nmsg/container.h"
#include "nmsg/msgmod.h"

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
test_alias(void)
{
/*
	assert(nmsg_init() == nmsg_res_success);
	assert(!strcmp("FSI", nmsg_alias_by_key(nmsg_alias_operator, 1)));
	assert(!strcmp("trafficconverter", nmsg_alias_by_key(nmsg_alias_group, 3)));
	assert(nmsg_alias_by_value(nmsg_alias_operator, "FSI") == 1);
*/

	return 0;
}

static int
test_chan_alias(void)
{
/*
	char **aliases;

	assert(nmsg_chalias_lookup("ch204", &aliases) > 0);
	nmsg_chalias_free(&aliases);
*/

	return 0;
}

static int
test_container(void)
{
/*
	nmsg_container_t c;
	nmsg_message_t m, *m_arr;
	nmsg_msgmod_t mm;
	uint8_t *tmpbuf;
	size_t i, tlen, m_len = 0;

	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mm != NULL);

	c = nmsg_container_init(NMSG_WBUFSZ_MAX);
	assert(c != NULL);

	m = nmsg_message_init(mm);
	assert(m != NULL);

	assert(nmsg_container_get_num_payloads(c) == 0);

	assert(nmsg_container_add(c, m) == nmsg_res_success);
	assert(nmsg_container_add(c, m) == nmsg_res_success);
	assert(nmsg_container_get_num_payloads(c) == 2);

	assert(nmsg_container_serialize(c, &tmpbuf, &tlen, 1, 0, 1, 123) == nmsg_res_success);
	assert(tlen == 50);

	assert(nmsg_container_deserialize(tmpbuf, tlen, &m_arr, &m_len) == nmsg_res_success);
	assert(m_len == 2);
	free(tmpbuf);

	for (i = 0; i < m_len; i++) {
		nmsg_message_destroy(&m_arr[i]);
	}

	nmsg_container_destroy(&c);
	assert(c == NULL);

	nmsg_message_destroy(&m);
	assert(m == NULL);
*/

	return 0;
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
	ret |= check(test_alias(), "test-misc");
	ret |= check(test_chan_alias(), "test-misc");
	ret |= check(test_container(), "test-misc");

	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
