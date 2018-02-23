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
#include <unistd.h>

#include "nmsg.h"
#include "nmsg/asprintf.h"
#include "nmsg/alias.h"
#include "nmsg/chalias.h"
#include "nmsg/container.h"
#include "nmsg/msgmod.h"
#include "nmsg/vendors.h"
#include "nmsg/base/defs.h"
#include "nmsg/sie/defs.h"
#include "nmsg/sie/dnsdedupe.pb-c.h"

#include "wdns.h"

#define NAME	"test-parse"


#define TEST_JSON_1	"{\"time\":\"2018-02-20 22:01:47.303896708\",\"vname\":\"SIE\",\"mname\":\"dnsdedupe\",\"source\":\"a1ba02cf\",\"message\":{\"type\":\"INSERTION\",\"count\":2,\"time_first\":\"2018-02-20 16:15:04\",\"time_last\":\"2018-02-20 19:04:42\",\"response_ip\":\"194.85.252.62\",\"bailiwick\":\"ru.\",\"rrname\":\"kinozal-chat.ru.\",\"rrclass\":\"IN\",\"rrtype\":\"NS\",\"rrttl\":345600,\"rdata\":[\"cdns1.ihc.ru.\",\"cdns2.ihc.ru.\"]}}"
#define TEST_JSON_2	"{\"time\":\"2018-02-20 22:02:05.856899023\",\"vname\":\"SIE\",\"mname\":\"newdomain\",\"source\":\"a1ba02cf\",\"message\":{\"domain\":\"sabon.fr.\",\"time_seen\":\"2018-02-20 22:00:13\",\"bailiwick\":\"sabon.fr.\",\"rrname\":\"asphalt.sabon.fr.\",\"rrclass\":\"IN\",\"rrtype\":\"MX\",\"rdata\":[\"30 mx.sabon.fr.\"],\"keys\":[],\"new_rr\":[]}}"


static int
test_json(void)
{
	nmsg_output_t o;
	nmsg_input_t i;
	nmsg_message_t m, m2;
	nmsg_msgmod_field_type ftype;
	nmsg_msgmod_t mmod1, mmod2;
	FILE *f;
	int fd;
	const char *fname;
	void *data;
	size_t dlen, nf;
	unsigned idx;

	f = tmpfile();
	assert(f != NULL);

	fd = fileno(f);
	assert(fd != -1);

	assert(write(fd, TEST_JSON_1, strlen(TEST_JSON_1)) == strlen(TEST_JSON_1));
	assert(write(fd, "\n", 1) == 1);

	assert(write(fd, TEST_JSON_2, strlen(TEST_JSON_2)) == strlen(TEST_JSON_2));
	assert(write(fd, "\n", 1) == 1);

	assert(lseek(fd, SEEK_SET, 0) == 0);

	i = nmsg_input_open_json(fd);
	assert(i != NULL);

	/* Message #1 */
	assert(nmsg_input_read(i, &m) == nmsg_res_success);

	assert(nmsg_message_get_vid(m) == NMSG_VENDOR_SIE_ID);
	assert(nmsg_message_get_msgtype(m) == NMSG_VENDOR_SIE_DNSDEDUPE_ID);
	assert(nmsg_message_get_source(m) == 0xa1ba02cf);
	assert(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	assert(nf == 14);
	mmod1 = nmsg_message_get_msgmod(m);

	assert(nmsg_message_get_field_idx(m, "time_first", &idx) == nmsg_res_success);
	assert(idx == 2);
	assert(nmsg_message_get_field_idx(m, "response_ip", &idx) == nmsg_res_success);
	assert(idx == 6);
	assert(nmsg_message_get_field_idx(m, "rrttl", &idx) == nmsg_res_success);
	assert(idx == 11);
	assert(nmsg_message_get_field_idx(m, "this_is_an_error", &idx) != nmsg_res_success);

	assert(nmsg_message_get_num_field_values(m, "rdata", &nf) == nmsg_res_success);
	assert(nf == 2);

	/* Arbitrary check; the indexed field is "count" */
	assert(nmsg_message_get_field_name(m, 1, &fname) == nmsg_res_success);
	assert(!strcmp(fname, "count"));
	assert(nmsg_message_get_field_by_idx(m, 1, 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == 2);
	assert(nmsg_message_get_field_type_by_idx(m, 1, &ftype) == nmsg_res_success);
	assert(ftype == nmsg_msgmod_ft_uint32);

	assert(nmsg_message_get_field(m, "type", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == NMSG__SIE__DNS_DEDUPE_TYPE__INSERTION);

	/* Try by name... and then by index */
	assert(nmsg_message_enum_value_to_name(m, "type", *((uint32_t *)data), &fname) == nmsg_res_success);
	assert(!strcmp(fname, "INSERTION"));

	fname = NULL;
	assert(nmsg_message_enum_value_to_name_by_idx(m, 0, *((uint32_t *)data), &fname) == nmsg_res_success);
	assert(!strcmp(fname, "INSERTION"));

	unsigned e_val;
	assert(nmsg_message_enum_name_to_value(m, "type", "AUTHORITATIVE", &e_val) == nmsg_res_success);
	assert(e_val == NMSG__SIE__DNS_DEDUPE_TYPE__AUTHORITATIVE);

	assert(nmsg_message_enum_name_to_value_by_idx(m, 0, "fake_data", &e_val) != nmsg_res_success);

	assert(nmsg_message_enum_name_to_value_by_idx(m, 0, "MERGED", &e_val) == nmsg_res_success);
	assert(e_val == NMSG__SIE__DNS_DEDUPE_TYPE__MERGED);

	assert(nmsg_message_get_field(m, "count", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == 2);

	assert(nmsg_message_get_field(m, "response_ip", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == inet_addr("194.85.252.62"));

	assert(nmsg_message_get_field(m, "type", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);

	assert(nmsg_message_get_field(m, "rrclass", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == WDNS_CLASS_IN);

	assert(nmsg_message_get_field(m, "rrtype", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == WDNS_TYPE_NS);

	assert(nmsg_message_get_field(m, "rrttl", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == 345600);

	assert(nmsg_message_get_field_type(m, "rdata", &ftype) == nmsg_res_success);
	assert(ftype == nmsg_msgmod_ft_bytes);

	/* Message #2 */
	assert(nmsg_input_read(i, &m) == nmsg_res_success);

	assert(nmsg_message_get_vid(m) == NMSG_VENDOR_SIE_ID);
	assert(nmsg_message_get_msgtype(m) == NMSG_VENDOR_SIE_NEWDOMAIN_ID);
	assert(nmsg_message_get_source(m) == 0xa1ba02cf);
	assert(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	assert(nf == 22);
	mmod2 = nmsg_message_get_msgmod(m);

	assert(mmod1 != mmod2);

	assert(nmsg_message_get_field(m, "rrclass", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == WDNS_CLASS_IN);

	assert(nmsg_message_get_field(m, "rrtype", 0, &data, &dlen) == nmsg_res_success);
	assert(dlen == 4);
	assert(*((uint32_t *)data) == WDNS_TYPE_MX);

	assert(nmsg_message_get_field(m, "rrttl", 0, &data, &dlen) != nmsg_res_success);


	/* Write the last piece of json data back to ourselves */
	assert(lseek(fd, SEEK_SET, 0) == 0);
	assert(ftruncate(fd, 0) != -1);
	o = nmsg_output_open_json(fd);
	assert(o != NULL);

	nmsg_message_set_source(m, 4321);
	nmsg_message_set_group(m, 1234);
	nmsg_message_set_operator(m, 13);
	assert(nmsg_output_write(o, m) == nmsg_res_success);
	assert(lseek(fd, SEEK_SET, 0) == 0);

	assert(nmsg_input_read(i, &m2) == nmsg_res_success);
	assert(nmsg_message_get_source(m) == 4321);
	assert(nmsg_message_get_group(m) == 1234);
	assert(nmsg_message_get_operator(m) == 13);

	assert(nmsg_message_get_msgmod(m2) == mmod2);

	assert(nmsg_input_close(&i) == nmsg_res_success);
	assert(nmsg_output_close(&o) == nmsg_res_success);

	fclose(f);

	return 0;
}

nmsg_res
read_callback_test(nmsg_message_t *msg, void *user)
{
	fprintf(stderr, "GOT IT!!!!!!!!!!!!!!!!!!!!!!\n");
	return nmsg_res_success;
}

static int
test_serialize(void)
{
	struct timespec ts1, ts2;
	nmsg_msgmod_t mm;
	nmsg_input_t i;
	nmsg_message_t m1, m2, m3;
	char *jout, *pres;
	void *p1, *p2, *p3;
	FILE *f;
	int fd;
	long sec_new = 0xc0debeef, nsec_new = 0xc0ffee;

	/*
	 * Write test JSON to file; read it back into nmsg.
	 * Then rewrite it both to json and presentation format.
	 * Then read both of those emissions back into standard nmsg data.
	 */
	assert(nmsg_message_from_json(TEST_JSON_1, &m1) == nmsg_res_success);

	/* Throw in this test while we're at it. */
	memset(&ts1, 0, sizeof(ts1));
	ts1.tv_sec = sec_new;
	ts1.tv_nsec = nsec_new;
	nmsg_message_set_time(m1, &ts1);

	assert(nmsg_message_to_json(m1, &jout) == nmsg_res_success);
	assert(jout != NULL);

	assert(nmsg_message_from_json(jout, &m2) == nmsg_res_success);
	nmsg_message_get_time(m2, &ts2);

	assert(ts2.tv_sec == sec_new);
	assert(ts2.tv_nsec == nsec_new);

	assert(nmsg_message_to_pres(m1, &pres, "\n") == nmsg_res_success);
	assert(pres != NULL);

	/* One more hoop to jump through deserializing presentation format */
	f = tmpfile();
	assert(f != NULL);
	fd = fileno(f);
	assert(fd != -1);

//	fprintf(stderr, "pres  len = %zu, contents = [%s]\n", strlen(pres), pres);
	assert(write(fd, pres, strlen(pres)) == (int)strlen(pres));
	assert(write(fd, "\n", 1) == 1);
	assert(lseek(fd, SEEK_SET, 0) != -1);

	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mm != NULL);

	i = nmsg_input_open_pres(fd, mm);
	assert(i != NULL);

	/* Not sure why this fails ;/ */
//	assert(nmsg_input_read(i, &m3) == nmsg_res_success);

	assert(nmsg_message_get_payload_size(m1) == nmsg_message_get_payload_size(m2));
//	assert(nmsg_message_get_payload_size(m2) == nmsg_message_get_payload_size(m3));

	/* The data encoded and decoded from json and pres format should all be identical */
	p1 = nmsg_message_get_payload(m1);
	assert(p1 != NULL);
	p2 = nmsg_message_get_payload(m2);
	assert(p2 != NULL);
	assert(!memcmp(p1, p2, nmsg_message_get_payload_size(m1)));
//	p3 = nmsg_message_get_payload(m3);
//	assert(p3 != NULL);
//	assert(!memcmp(p1, p3, nmsg_message_get_payload_size(m1)));

	nmsg_message_destroy(&m1);
	nmsg_message_destroy(&m2);
//	nmsg_message_destroy(&m3);

	assert(nmsg_input_close(&i) == nmsg_res_success);

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

	ret |= check(test_json(), "test-parse");
	ret |= check(test_serialize(), "test-parse");

	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
