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
fill_message(nmsg_message_t m)
{
	size_t nf, i;

	assert(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	assert(nf != 0);

	for (i = 0; i < nf; i++) {
		assert(nmsg_message_set_field_by_idx(m, i, 0, (const uint8_t *)"ABCD", 4) == nmsg_res_success);
	}

	return 0;
}

static int
cmp_nmessages(nmsg_message_t m1, nmsg_message_t m2)
{
	size_t nf1, nf2, i;

	assert(nmsg_message_get_num_fields(m1, &nf1) == nmsg_res_success);
	assert(nmsg_message_get_num_fields(m2, &nf2) == nmsg_res_success);

	if (!nf1 && !nf2)
		return 0;
	else if (nf1 < nf2)
		return -1;
	else if (nf1 > nf2)
		return 1;

	for (i = 0; i < nf1; i++) {
		nmsg_msgmod_field_type ftype1, ftype2;
		const char *name1, *name2;
		size_t nfv1, nfv2;
		unsigned int flags1, flags2;

		assert(nmsg_message_get_num_field_values_by_idx(m1, i, &nfv1) == nmsg_res_success);
		assert(nmsg_message_get_num_field_values_by_idx(m2, i, &nfv2) == nmsg_res_success);

		if (nfv1 < nfv2)
			return -1;
		else if (nfv1 > nfv2)
			return 1;

		assert(nmsg_message_get_field_flags_by_idx(m1, i, &flags1) == nmsg_res_success);
		assert(nmsg_message_get_field_flags_by_idx(m2, i, &flags2) == nmsg_res_success);

		if (flags1 < flags2)
			return -1;
		else if (flags1 > flags2)
			return 1;

		assert(nmsg_message_get_field_type_by_idx(m1, i, &ftype1) == nmsg_res_success);
		assert(nmsg_message_get_field_type_by_idx(m2, i, &ftype2) == nmsg_res_success);

		if (ftype1 < ftype2)
			return -1;
		else if (ftype2 > ftype1)
			return 1;

		assert(nmsg_message_get_field_name(m1, i, &name1) == nmsg_res_success);
		assert(nmsg_message_get_field_name(m2, i, &name2) == nmsg_res_success);

		if (strcmp(name1, name2))
			return (strcmp(name1, name2));


//		fprintf(stderr, "hehe: %zu, %zu\n", nfv1, nfv2);
	}

	return 0;
}

static int
test_container(void)
{
	nmsg_container_t c;
	nmsg_message_t m1, m2, m3, *m_arr1, *m_arr2;
	nmsg_msgmod_t mm;
	uint8_t *tmpbuf1, *tmpbuf2;
	size_t i, tlen1, tlen2, m_len = 0;

	/* XXX: remove this line */
	return 0;

	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mm != NULL);

	c = nmsg_container_init(NMSG_WBUFSZ_MAX);
	assert(c != NULL);

	m1 = nmsg_message_init(mm);
	assert(m1 != NULL);

	fill_message(m1);

	m2 = nmsg_message_init(mm);
	assert(m2 != NULL);

	uint8_t *payload = malloc(4);
	memcpy(payload, "data", 4);
	m3 = nmsg_message_from_raw_payload(NMSG_VENDOR_BASE_ID, 0, payload, 4, NULL);
	assert(m3 != NULL);

	assert(nmsg_container_get_num_payloads(c) == 0);

	assert(nmsg_container_add(c, m1) == nmsg_res_success);

#define REPEAT_FIELD	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	nmsg_message_set_field_by_idx(m2, 0, 0, (const uint8_t *)REPEAT_FIELD, strlen(REPEAT_FIELD));
	assert(nmsg_container_add(c, m2) == nmsg_res_success);
	assert(nmsg_container_get_num_payloads(c) == 2);

	assert(nmsg_container_add(c, m3) == nmsg_res_success);

	/* First try without zlib compression. */
	assert(nmsg_container_serialize(c, &tmpbuf1, &tlen1, 1, 0, 1, 123) == nmsg_res_success);

	/* Then use compression. */
	assert(nmsg_container_serialize(c, &tmpbuf2, &tlen2, 1, 1, 1, 123) == nmsg_res_success);

	/* The second result should be smaller. */
	assert(tlen2 < tlen1);

	/* Try deserializing the uncompressed version. */
	assert(nmsg_container_deserialize(tmpbuf1, tlen1, &m_arr1, &m_len) == nmsg_res_success);
	assert(m_len == 3);
	free(tmpbuf1);

	/* Also verify the compressed variant. */
	assert(nmsg_container_deserialize(tmpbuf2, tlen2, &m_arr2, &m_len) == nmsg_res_success);
	assert(m_len == 3);
	free(tmpbuf2);

	assert(cmp_nmessages(m1, m_arr1[0]) == 0);
	assert(cmp_nmessages(m2, m_arr1[1]) == 0);

	assert(cmp_nmessages(m1, m_arr2[0]) == 0);
	assert(cmp_nmessages(m2, m_arr2[1]) == 0);

	/* The last nmsg should actually seem corrupt. */
	size_t tnf;
	assert(nmsg_message_get_num_fields(m3, &tnf) == nmsg_message_get_num_fields(m_arr1[2], &tnf));
	assert(nmsg_message_get_num_fields(m3, &tnf) == nmsg_message_get_num_fields(m_arr2[2], &tnf));

	for (i = 0; i < m_len; i++) {
		nmsg_message_destroy(&m_arr1[i]);
		nmsg_message_destroy(&m_arr2[i]);
	}

	nmsg_message_destroy(&m1);
	assert(m1 == NULL);

	nmsg_message_destroy(&m2);
	assert(m2 == NULL);

	nmsg_message_destroy(&m3);
	assert(m3 == NULL);

	nmsg_container_destroy(&c);
	assert(c == NULL);

	return 0;
}

static int
test_zbuf(void)
{
	nmsg_zbuf_t zd, zi;

	zd = nmsg_zbuf_deflate_init();
	assert(zd != NULL);

	zi = nmsg_zbuf_inflate_init();
	assert(zi != NULL);

#define BLEN	4096
	u_char tmpbuf[BLEN], outbuf[BLEN * 2];
	size_t zlen = sizeof(outbuf);

	memset(tmpbuf, 0x41, BLEN);

	/* Try compressing a buffer with lots of repetition. It should shrink
	   down in size noticeably from the original. */
	assert(nmsg_zbuf_deflate(zd, BLEN, tmpbuf, &zlen, outbuf) == nmsg_res_success);
	assert(zlen < sizeof(tmpbuf));

	/* Now decompress the buffer and make sure it matches the original data. */
	u_char *ubuf;
	size_t ulen;
	assert(nmsg_zbuf_inflate(zi, zlen, outbuf, &ulen, &ubuf) == nmsg_res_success);
	assert(ulen == BLEN);
	assert(!memcmp(ubuf, tmpbuf, ulen));
	free(ubuf);

	/* Try compressing a buffer without repetition. It must necessarily be at
	   least as large as the original since there are no patterns. */
	strcpy((char *)tmpbuf, "the quick brown lazy dgs");
	zlen = sizeof(outbuf);
	assert(nmsg_zbuf_deflate(zd, strlen((char *)tmpbuf), tmpbuf, &zlen, outbuf) == nmsg_res_success);
	assert(zlen >= strlen((char *)tmpbuf));

	/* Do the same decompression check against the second data set. */
	assert(nmsg_zbuf_inflate(zi, zlen, outbuf, &ulen, &ubuf) == nmsg_res_success);
	assert(ulen == strlen((char *)tmpbuf));
	assert(!memcmp(ubuf, tmpbuf, ulen));
	free(ubuf);

	nmsg_zbuf_destroy(&zd);
	assert(zd == NULL);

	nmsg_zbuf_destroy(&zi);
	assert(zi == NULL);

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

	assert(nmsg_init() == nmsg_res_success);

	ret |= check(test_printf(), "test-misc");
	ret |= check(test_alias(), "test-misc");
	ret |= check(test_chan_alias(), "test-misc");
	ret |= check(test_container(), "test-misc");
	ret |= check(test_zbuf(), "test-misc");

	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
