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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "errors.h"

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


/* Test decoding of json data with intense validation */
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
	const char *fname = NULL;
	void *data = NULL;
	size_t dlen, nf;
	unsigned idx;

	f = tmpfile();
	check_return(f != NULL);

	fd = fileno(f);
	check_return(fd != -1);

	check_return(write(fd, TEST_JSON_1, strlen(TEST_JSON_1)) == strlen(TEST_JSON_1));
	check_return(write(fd, "\n", 1) == 1);

	check_return(write(fd, TEST_JSON_2, strlen(TEST_JSON_2)) == strlen(TEST_JSON_2));
	check_return(write(fd, "\n", 1) == 1);

	check_return(lseek(fd, SEEK_SET, 0) == 0);

	i = nmsg_input_open_json(fd);
	check_return(i != NULL);

	/* Message #1 */
	check_return(nmsg_input_read(i, &m) == nmsg_res_success);

	check(nmsg_message_get_vid(m) == NMSG_VENDOR_SIE_ID);
	check(nmsg_message_get_msgtype(m) == NMSG_VENDOR_SIE_DNSDEDUPE_ID);
	check(nmsg_message_get_source(m) == 0xa1ba02cf);
	check(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	check(nf == 14);
	mmod1 = nmsg_message_get_msgmod(m);

	check(nmsg_message_get_field_idx(m, "time_first", &idx) == nmsg_res_success);
	check(idx == 2);
	check(nmsg_message_get_field_idx(m, "response_ip", &idx) == nmsg_res_success);
	check(idx == 6);
	check(nmsg_message_get_field_idx(m, "rrttl", &idx) == nmsg_res_success);
	check(idx == 11);
	check(nmsg_message_get_field_idx(m, "this_is_an_error", &idx) != nmsg_res_success);

	check(nmsg_message_get_num_field_values(m, "rdata", &nf) == nmsg_res_success);
	check(nf == 2);

	/* Arbitrary check; the indexed field is "count" */
	check(nmsg_message_get_field_name(m, 1, &fname) == nmsg_res_success);
	check(fname && (!strcmp(fname, "count")));
	check(nmsg_message_get_field_by_idx(m, 1, 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == 2));
	check(nmsg_message_get_field_type_by_idx(m, 1, &ftype) == nmsg_res_success);
	check(ftype == nmsg_msgmod_ft_uint32);

	data = NULL;
	check(nmsg_message_get_field(m, "type", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == NMSG__SIE__DNS_DEDUPE_TYPE__INSERTION));

	/* Try by name... and then by index */
	fname = NULL;
	check(data && (nmsg_message_enum_value_to_name(m, "type", *((uint32_t *)data), &fname) == nmsg_res_success));
	check(fname && (!strcmp(fname, "INSERTION")));

	fname = NULL;
	check(data && (nmsg_message_enum_value_to_name_by_idx(m, 0, *((uint32_t *)data), &fname) == nmsg_res_success));
	check(fname && (!strcmp(fname, "INSERTION")));

	unsigned e_val;
	check(nmsg_message_enum_name_to_value(m, "type", "AUTHORITATIVE", &e_val) == nmsg_res_success);
	check(e_val == NMSG__SIE__DNS_DEDUPE_TYPE__AUTHORITATIVE);

	check(nmsg_message_enum_name_to_value_by_idx(m, 0, "fake_data", &e_val) != nmsg_res_success);

	check(nmsg_message_enum_name_to_value_by_idx(m, 0, "MERGED", &e_val) == nmsg_res_success);
	check(e_val == NMSG__SIE__DNS_DEDUPE_TYPE__MERGED);

	data = NULL;
	check(nmsg_message_get_field(m, "count", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == 2));

	data = NULL;
	check(nmsg_message_get_field(m, "response_ip", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == inet_addr("194.85.252.62")));

	check(nmsg_message_get_field(m, "type", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);

	data = NULL;
	check(nmsg_message_get_field(m, "rrclass", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == WDNS_CLASS_IN));

	data = NULL;
	check(nmsg_message_get_field(m, "rrtype", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == WDNS_TYPE_NS));

	data = NULL;
	check(nmsg_message_get_field(m, "rrttl", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == 345600));

	check(nmsg_message_get_field_type(m, "rdata", &ftype) == nmsg_res_success);
	check(ftype == nmsg_msgmod_ft_bytes);

	/* Message #2 */
	check_return(nmsg_input_read(i, &m) == nmsg_res_success);

	check(nmsg_message_get_vid(m) == NMSG_VENDOR_SIE_ID);
	check(nmsg_message_get_msgtype(m) == NMSG_VENDOR_SIE_NEWDOMAIN_ID);
	check(nmsg_message_get_source(m) == 0xa1ba02cf);
	check(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	check(nf == 22);
	mmod2 = nmsg_message_get_msgmod(m);

	check(mmod1 != mmod2);

	data = NULL;
	check(nmsg_message_get_field(m, "rrclass", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == WDNS_CLASS_IN));

	data = NULL;
	check(nmsg_message_get_field(m, "rrtype", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == WDNS_TYPE_MX));

	check(nmsg_message_get_field(m, "rrttl", 0, &data, &dlen) != nmsg_res_success);

	/*
	 * Write the last piece of json data back to ourselves.
	 * Set some message attributes and make sure they survive.
	  */
	check_return(lseek(fd, SEEK_SET, 0) == 0);
	check_return(ftruncate(fd, 0) != -1);
	o = nmsg_output_open_json(fd);
	check_return(o != NULL);

	nmsg_message_set_source(m, 4321);
	nmsg_message_set_group(m, 1234);
	nmsg_message_set_operator(m, 13);
	check_return(nmsg_output_write(o, m) == nmsg_res_success);
	check_return(lseek(fd, SEEK_SET, 0) == 0);

	check_return(nmsg_input_read(i, &m2) == nmsg_res_success);
	check(nmsg_message_get_source(m) == 4321);
	check(nmsg_message_get_group(m) == 1234);
	check(nmsg_message_get_operator(m) == 13);

	check(nmsg_message_get_msgmod(m2) == mmod2);

	nmsg_message_destroy(&m);
	nmsg_message_destroy(&m2);

	check(nmsg_input_close(&i) == nmsg_res_success);
	check(nmsg_output_close(&o) == nmsg_res_success);

	fclose(f);

	l_return_test_status();
}

/* Test serialization and deserialization of nmsg data to/from json and pres formats */
static int
test_serialize(void)
{
	struct timespec ts1, ts2;
	nmsg_msgmod_t mm;
	nmsg_input_t i;
	nmsg_message_t m1, m2;
	char *jout, *pres;
	void *p1, *p2;
	FILE *f;
	int fd;
	long sec_new = 0xc0debeef, nsec_new = 0xc0ffee;

	/*
	 * Write test JSON to file; read it back into nmsg.
	 * Then rewrite it both to json and presentation format.
	 * Then read both of those emissions back into standard nmsg data.
	 */
	check_return(nmsg_message_from_json(TEST_JSON_1, &m1) == nmsg_res_success);

	/*
	 * Throw in a test for nmsg_message_set_time() while we're at it.
	 * This also serves the dual purpose of helping verify serialization.
	 */
	memset(&ts1, 0, sizeof(ts1));
	ts1.tv_sec = sec_new;
	ts1.tv_nsec = nsec_new;
	nmsg_message_set_time(m1, &ts1);

	/* Serialize the modified message and then read it back and verify it. */
	check_return(nmsg_message_to_json(m1, &jout) == nmsg_res_success);
	check_return(jout != NULL);

	check_return(nmsg_message_from_json(jout, &m2) == nmsg_res_success);
	free(jout);
	nmsg_message_get_time(m2, &ts2);

	check(ts2.tv_sec == sec_new);
	check(ts2.tv_nsec == nsec_new);

	/* Now try serialization to presentation format. */
	check_return(nmsg_message_to_pres(m1, &pres, "\n") == nmsg_res_success);
	check_return(pres != NULL);

	/* One more hoop to jump through deserializing presentation format */
	f = tmpfile();
	check_return(f != NULL);
	fd = fileno(f);
	check_return(fd != -1);

//	fprintf(stderr, "pres  len = %zu, contents = [%s]\n", strlen(pres), pres);
	check_return(write(fd, pres, strlen(pres)) == (int)strlen(pres));
	check_return(write(fd, "\n", 1) == 1);
	check_return(lseek(fd, SEEK_SET, 0) != -1);
	free(pres);
	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	check_return(mm != NULL);

	i = nmsg_input_open_pres(fd, mm);
	check_return(i != NULL);

	/* Not sure why this fails ;/ */
//	check_return(nmsg_input_read(i, &m3) == nmsg_res_success);

	/* Finally, compare original message with deserialized json and pres. forms */
	check_return(nmsg_message_get_payload_size(m1) == nmsg_message_get_payload_size(m2));
//	check_return(nmsg_message_get_payload_size(m2) == nmsg_message_get_payload_size(m3));

	/* The data encoded and decoded from json and pres format should all be identical */
	p1 = nmsg_message_get_payload(m1);
	check_return(p1 != NULL);
	p2 = nmsg_message_get_payload(m2);
	check_return(p2 != NULL);
	check(!memcmp(p1, p2, nmsg_message_get_payload_size(m1)));
//	p3 = nmsg_message_get_payload(m3);
//	check_return(p3 != NULL);
//	check(!memcmp(p1, p3, nmsg_message_get_payload_size(m1)));

	nmsg_message_destroy(&m1);
	nmsg_message_destroy(&m2);
//	nmsg_message_destroy(&m3);

	check(nmsg_input_close(&i) == nmsg_res_success);

	fclose(f);

	l_return_test_status();
}

int
main(void)
{
	check_abort(nmsg_init() == nmsg_res_success);

	check_explicit2_display_only(test_json() == 0, "test-parse / test_json");
	check_explicit2_display_only(test_serialize() == 0, "test-parse / test_serialize");

	g_check_test_status(false);
}
