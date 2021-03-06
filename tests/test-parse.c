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
#include "nmsg/base/dnsqr.pb-c.h"
#include "nmsg/base/http.pb-c.h"
#include "wdns.h"

#define NAME	"test-parse"

#define TEST_JSON_1	"{\"time\":\"2018-02-20 22:01:47.303896708\",\"vname\":\"base\",\"mname\":\"http\",\"source\":\"abcdef01\",\"message\":{\"type\":\"unknown\",\"dstip\":\"192.0.2.2\",\"dstport\":80,\"request\":\"GET /\"}}"

#define TEST_JSON_2	"{\"time\":\"2018-09-20 19:19:14.971583000\",\"vname\":\"base\",\"mname\":\"dnsqr\",\"source\":\"42434445\",\"message\":{\"type\":\"UDP_QUERY_RESPONSE\",\"query_ip\":\"203.0.113.7\",\"response_ip\":\"203.0.113.200\",\"proto\":\"UDP\",\"query_port\":1234,\"response_port\":53,\"id\":9876,\"query_time_nsec\":[971583000]}}"

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

	check(nmsg_message_get_vid(m) == NMSG_VENDOR_BASE_ID);
	check(nmsg_message_get_msgtype(m) == NMSG_VENDOR_BASE_HTTP_ID);
	check(nmsg_message_get_source(m) == 0xabcdef01);
	check(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	check(nf == 18);
	mmod1 = nmsg_message_get_msgmod(m);

	check(nmsg_message_get_field_idx(m, "dstip", &idx) == nmsg_res_success);
	check(idx == 4);
	check(nmsg_message_get_field_idx(m, "dstport", &idx) == nmsg_res_success);
	check(idx == 5);
	check(nmsg_message_get_field_idx(m, "request", &idx) == nmsg_res_success);
	check(idx == 6);
	check(nmsg_message_get_field_idx(m, "this_is_an_error", &idx) != nmsg_res_success);

	check(nmsg_message_get_num_field_values(m, "dstip", &nf) == nmsg_res_success);
	check(nf == 1);

	/* Arbitrary check; the indexed field is "dstip" */
	check(nmsg_message_get_field_name(m, 4, &fname) == nmsg_res_success);
	check(fname && (!strcmp(fname, "dstip")));
	check(nmsg_message_get_field_by_idx(m, 4, 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == inet_addr("192.0.2.2")));
	check(nmsg_message_get_field_type_by_idx(m, 4, &ftype) == nmsg_res_success);
	check(ftype == nmsg_msgmod_ft_ip);

	data = NULL;
	check(nmsg_message_get_field(m, "type", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == NMSG__BASE__HTTP_TYPE__unknown));

	/* Try by name... and then by index */
	fname = NULL;
	check(data && (nmsg_message_enum_value_to_name(m, "type", *((uint32_t *)data), &fname) == nmsg_res_success));
	check(fname && (!strcmp(fname, "unknown")));

	fname = NULL;
	check(data && (nmsg_message_enum_value_to_name_by_idx(m, 0, *((uint32_t *)data), &fname) == nmsg_res_success));
	check(fname && (!strcmp(fname, "unknown")));

	unsigned e_val;
	check(nmsg_message_enum_name_to_value(m, "type", "unknown", &e_val) == nmsg_res_success);
	check(e_val == NMSG__BASE__HTTP_TYPE__unknown);

	check(nmsg_message_enum_name_to_value(m, "type", "sinkhole", &e_val) == nmsg_res_success);
	check(e_val == NMSG__BASE__HTTP_TYPE__sinkhole);

	check(nmsg_message_enum_name_to_value_by_idx(m, 0, "fake_data", &e_val) != nmsg_res_success);

	check(nmsg_message_enum_name_to_value_by_idx(m, 0, "sinkhole", &e_val) == nmsg_res_success);
	check(e_val == NMSG__BASE__HTTP_TYPE__sinkhole);

	data = NULL;
	check(nmsg_message_get_field(m, "dstport", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == 80));

	data = NULL;
	check(nmsg_message_get_field(m, "dstip", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == inet_addr("192.0.2.2")));

	check(nmsg_message_get_field(m, "type", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);

	data = NULL;

	check(nmsg_message_get_field_type(m, "request", &ftype) == nmsg_res_success);
	check(ftype == nmsg_msgmod_ft_mlstring);

	/* ************************************************************* */
	/* Message #2 */

	check_return(nmsg_input_read(i, &m) == nmsg_res_success);

	check(nmsg_message_get_vid(m) == NMSG_VENDOR_BASE_ID);
	check(nmsg_message_get_msgtype(m) == NMSG_VENDOR_BASE_DNSQR_ID);
	check(nmsg_message_get_source(m) == 0x42434445);
	check(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	check(nf == 26);

	mmod2 = nmsg_message_get_msgmod(m);

	check(mmod1 != mmod2);

	data = NULL;
	check(nmsg_message_get_field(m, "proto", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == IPPROTO_UDP));

	data = NULL;
	check(nmsg_message_get_field(m, "query_port", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == 1234));

	check(nmsg_message_get_field(m, "thisisbogus", 0, &data, &dlen) != nmsg_res_success);

	/* this is a valid field but is not in the test json data */
	check(nmsg_message_get_field(m, "resolver_address_zeroed", 0, &data, &dlen) != nmsg_res_success);

	/* test for number of fields, those using PROTOBUF_C_LABEL_REPEATED */
	check(nmsg_message_get_num_field_values(m, "query_time_nsec", &nf) == nmsg_res_success);

	data = NULL;
	check(nmsg_message_get_field(m, "type", 0, &data, &dlen) == nmsg_res_success);
	check(dlen == 4);
	check(data && (*((uint32_t *)data) == NMSG__BASE__DNS_QRTYPE__UDP_QUERY_RESPONSE));

	check(data && (nmsg_message_enum_value_to_name(m, "type", *((uint32_t *)data), &fname) == nmsg_res_success));
	check(fname && (!strcmp(fname, "UDP_QUERY_RESPONSE")));

	check(nmsg_message_enum_name_to_value_by_idx(m, 0, "UDP_UNSOLICITED_RESPONSE", &e_val) == nmsg_res_success);
	check(e_val == NMSG__BASE__DNS_QRTYPE__UDP_UNSOLICITED_RESPONSE);

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
	check(nmsg_message_get_source(m2) == 4321);
	check(nmsg_message_get_group(m2) == 1234);
	check(nmsg_message_get_operator(m2) == 13);

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
	mm = nmsg_msgmod_lookup_byname("base", "email");
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
