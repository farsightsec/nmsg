/*
 * Copyright (c) 2018, 2021 by Farsight Security, Inc.
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
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <pthread.h>

#include "errors.h"

#include "nmsg.h"
#include "nmsg/asprintf.h"
#include "nmsg/alias.h"
#include "nmsg/chalias.h"
#include "nmsg/container.h"
#include "nmsg/msgmod.h"
#include "nmsg/vendors.h"
#include "nmsg/base/defs.h"

#include "libmy/fast_inet_ntop.h"

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

static int
assert_buf(char **buf, int bsize, int expected)
{
	check(bsize == expected);
	check_return(*buf != NULL);
	free(*buf);
	*buf = NULL;

	return 0;
}

static int
test_alias(void)
{
	const char *salias;

	check((salias = nmsg_alias_by_key(nmsg_alias_operator, 1)) != NULL);

	if (salias)
		check(!strcmp("FSI", salias));

	check((salias = nmsg_alias_by_key(nmsg_alias_group, 3)) != NULL);

	if (salias)
		check(!strcmp("trafficconverter", salias));

	check(nmsg_alias_by_value(nmsg_alias_operator, "FSI") == 1);

	l_return_test_status();
}

static int
test_chan_alias(void)
{
	char **aliases;

	check_return(setenv("NMSG_CHALIAS_FILE", SRCDIR "/tests/generic-tests/test.chalias", 1) == 0);
	check_return(nmsg_chalias_lookup("ch204", &aliases) > 0);
	nmsg_chalias_free(&aliases);

	check_return(nmsg_chalias_lookup("chtest1", &aliases) > 0);
	nmsg_chalias_free(&aliases);

	check_return(nmsg_chalias_lookup("chtest_nxist", &aliases) == 0);
	nmsg_chalias_free(&aliases);

	l_return_test_status();
}

static int
test_strbuf(void)
{
	struct nmsg_strbuf *sb;

	sb = nmsg_strbuf_init();
	check_return(sb != NULL);

	check(nmsg_strbuf_append(sb, "%s %.4lx", "hello", 0x666) == nmsg_res_success);
	check(nmsg_strbuf_len(sb) == 10);
	check(!strcmp(sb->data, "hello 0666"));

	check(nmsg_strbuf_reset(sb) == nmsg_res_success);
	check(nmsg_strbuf_len(sb) == 0);

	nmsg_strbuf_destroy(&sb);
	check(sb == NULL);

	l_return_test_status();
}

static int
test_strbuf_json(void)
{
	struct nmsg_strbuf *sb;
	const char test[]="\b\f\n\r\t\"\\";
	const char result[]="\\b\\f\\n\\r\\t\\\"\\\\";

	sb = nmsg_strbuf_init();
	check_return(sb != NULL);

	check(nmsg_strbuf_append_str_json(sb, test, sizeof(test) - 1) == nmsg_res_success);
	check(nmsg_strbuf_len(sb) == strlen(result));
	check(strcmp(result, sb->data) == 0);

	nmsg_strbuf_destroy(&sb);
	check(sb == NULL);

	l_return_test_status();
}

/* Test the random number generation functions */
static int
test_random(void)
{
	nmsg_random_t r;
	uint32_t r1, r2;
	uint8_t b1[16], b2[16];

	r = nmsg_random_init();
	check_return(r != NULL);

	r1 = nmsg_random_uint32(r);
	r2 = nmsg_random_uint32(r);

	/* Well, this isn't necessarily true. But it's rather unlikely. */
	check(r1 != r2);

	r2 = nmsg_random_uniform(r, 600);
	check(r2 <= 600);

	memset(b1, 0, sizeof(b1));
	memset(b2, 0, sizeof(b2));
	check_return(!memcmp(b1, b2, sizeof(b1)));
	nmsg_random_buf(r, b1, sizeof(b1));
	check(memcmp(b1, b2, sizeof(b1)));

	nmsg_random_destroy(&r);
	check(r == NULL);

	l_return_test_status();
}

/* Fill a blank? message object with nonsense. */
static int
fill_message(nmsg_message_t m)
{
	size_t nf, i;

	check_return(nmsg_message_get_num_fields(m, &nf) == nmsg_res_success);
	check_return(nf != 0);

	for (i = 0; i < nf; i++) {
		check_return(nmsg_message_set_field_by_idx(m, i, 0, (const uint8_t *)"ABCD", 4) == nmsg_res_success);
	}

	return 0;
}

/*
 * Compare two nmsg message objects for equality.
 *
 * Since this is a leaf function called by other tests,
 * we don't even bother with returning 1 or -1;
 * any non-zero return is simply treated an error.
 */
static int
cmp_nmessages(nmsg_message_t m1, nmsg_message_t m2)
{
	size_t nf1, nf2, i;

	check_return(nmsg_message_get_num_fields(m1, &nf1) == nmsg_res_success);
	check_return(nmsg_message_get_num_fields(m2, &nf2) == nmsg_res_success);

	if (!nf1 && !nf2)
		return 0;

	check_return_silent(nf1 == nf2);

	for (i = 0; i < nf1; i++) {
		nmsg_msgmod_field_type ftype1, ftype2;
		const char *name1, *name2;
		size_t nfv1, nfv2;
		unsigned int flags1, flags2;

		check_return(nmsg_message_get_num_field_values_by_idx(m1, i, &nfv1) == nmsg_res_success);
		check_return(nmsg_message_get_num_field_values_by_idx(m2, i, &nfv2) == nmsg_res_success);

		check_return_silent(nfv1 == nfv2);

		check_return(nmsg_message_get_field_flags_by_idx(m1, i, &flags1) == nmsg_res_success);
		check_return(nmsg_message_get_field_flags_by_idx(m2, i, &flags2) == nmsg_res_success);

		check_return_silent(flags1 ==  flags2);

		check_return(nmsg_message_get_field_type_by_idx(m1, i, &ftype1) == nmsg_res_success);
		check_return(nmsg_message_get_field_type_by_idx(m2, i, &ftype2) == nmsg_res_success);

		check_return_silent(ftype1 == ftype2);

		check_return(nmsg_message_get_field_name(m1, i, &name1) == nmsg_res_success);
		check_return(nmsg_message_get_field_name(m2, i, &name2) == nmsg_res_success);

		check_return_silent(!strcmp(name1, name2));

	}

	return 0;
}

/* Test container creation, modification, and (de)serialization. */
static int
test_container(void)
{
	nmsg_container_t c;
	nmsg_message_t m1, m2, m3, *m_arr1, *m_arr2;
	nmsg_msgmod_t mm;
	uint8_t *tmpbuf1, *tmpbuf2, *payload;
	size_t i, tlen1, tlen2, m_len = 0;
	int failed = 0;

	/* This should fail. */
	c = nmsg_container_init(0);
	check_return(c == NULL);

	/*
	 * This container should initialize properly and then eventually
	 * fail when it fills up because it is too small.
	 */
	c = nmsg_container_init(1024);

	mm = nmsg_msgmod_lookup_byname("base", "http");
	check_return(mm != NULL);

	m1 = nmsg_message_init(mm);
	check_return(m1 != NULL);

	return_if_error(fill_message(m1));

	for (i = 0; i < 12; i++) {

		if (nmsg_container_add(c, m1) != nmsg_res_success) {
			failed = 1;
			break;
		}

	}

	check(failed != 0);

	nmsg_container_destroy(&c);

	/*
	 * Now onto the main test.
	 * Create a container and verify the messages are added to it
	 * successfully and payloads adjusted accordingly.
	 */
	c = nmsg_container_init(NMSG_WBUFSZ_MAX);
	check_return(c != NULL);

	m2 = nmsg_message_init(mm);
	check_return(m2 != NULL);

	payload = malloc(4);
	check_abort(payload != NULL);
	memcpy(payload, "data", 4);
	m3 = nmsg_message_from_raw_payload(NMSG_VENDOR_BASE_ID, 0, payload, 4, NULL);
	check_return(m3 != NULL);

	check(nmsg_container_get_num_payloads(c) == 0);

	check_return(nmsg_container_add(c, m1) == nmsg_res_success);

	/* Test compression. First add a message with an easily compressable field. */
#define REPEAT_FIELD	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	nmsg_message_set_field_by_idx(m2, 0, 0, (const uint8_t *)REPEAT_FIELD, strlen(REPEAT_FIELD));
	check_return(nmsg_container_add(c, m2) == nmsg_res_success);
	check_return(nmsg_container_get_num_payloads(c) == 2);

	check_return(nmsg_container_add(c, m3) == nmsg_res_success);

	/* First try serialization without zlib compression. */
	check_return(nmsg_container_serialize(c, &tmpbuf1, &tlen1, 1, 0, 1, 123) == nmsg_res_success);

	/* Then do it with compression. */
	check_return(nmsg_container_serialize(c, &tmpbuf2, &tlen2, 1, 1, 1, 123) == nmsg_res_success);

	/* The second result (compressed serialized) should be smaller. */
	check(tlen2 < tlen1);

	/* Try deserializing the uncompressed version. */
	check_return(nmsg_container_deserialize(tmpbuf1, tlen1, &m_arr1, &m_len) == nmsg_res_success);
	check_return(m_len == 3);
	free(tmpbuf1);

	/* Also verify the compressed variant. */
	check_return(nmsg_container_deserialize(tmpbuf2, tlen2, &m_arr2, &m_len) == nmsg_res_success);
	check_return(m_len == 3);
	free(tmpbuf2);

	/* Both deserialized messages should look the same. */
	return_if_error(cmp_nmessages(m1, m_arr1[0]));
	return_if_error(cmp_nmessages(m2, m_arr1[1]));

	return_if_error(cmp_nmessages(m1, m_arr2[0]));
	return_if_error(cmp_nmessages(m2, m_arr2[1]));

	/* Skip over the last nmsg because it should seem corrupt. */
	size_t tnf;
	check(nmsg_message_get_num_fields(m3, &tnf) == nmsg_message_get_num_fields(m_arr1[2], &tnf));
	check(nmsg_message_get_num_fields(m3, &tnf) == nmsg_message_get_num_fields(m_arr2[2], &tnf));

	for (i = 0; i < m_len; i++) {
		nmsg_message_destroy(&m_arr1[i]);
		nmsg_message_destroy(&m_arr2[i]);
	}

	free(m_arr1);
	free(m_arr2);

	nmsg_message_destroy(&m1);
	check(m1 == NULL);

	nmsg_message_destroy(&m2);
	check(m2 == NULL);

	nmsg_message_destroy(&m3);
	check(m3 == NULL);

	nmsg_container_destroy(&c);
	check(c == NULL);

	l_return_test_status();
}

/* Test zbuf inflation and deflation */
static int
test_zbuf(void)
{
	nmsg_zbuf_t zd, zi;
#define BLEN	4096
	u_char tmpbuf[BLEN], outbuf[BLEN * 2];
	size_t zlen = sizeof(outbuf);

	zd = nmsg_zbuf_deflate_init();
	check_return(zd != NULL);

	zi = nmsg_zbuf_inflate_init();
	check_return(zi != NULL);

	memset(tmpbuf, 0x41, BLEN);

	/* Try compressing a buffer with lots of repetition. It should shrink
	   down in size noticeably from the original. */
	check_return(nmsg_zbuf_deflate(zd, BLEN, tmpbuf, &zlen, outbuf) == nmsg_res_success);
	check(zlen < sizeof(tmpbuf));

	/* Now decompress the buffer and make sure it matches the original data. */
	u_char *ubuf;
	size_t ulen;
	check_return(nmsg_zbuf_inflate(zi, zlen, outbuf, &ulen, &ubuf) == nmsg_res_success);
	check_return(ulen == BLEN);
	check(!memcmp(ubuf, tmpbuf, ulen));
	free(ubuf);

	/* Try compressing a buffer without repetition. It must necessarily be at
	   least as large as the original since there are no patterns. */
	strcpy((char *)tmpbuf, "the quick brown lazy dgs");
	zlen = sizeof(outbuf);
	check_return(nmsg_zbuf_deflate(zd, strlen((char *)tmpbuf), tmpbuf, &zlen, outbuf) == nmsg_res_success);
	check(zlen >= strlen((char *)tmpbuf));

	/* Do the same decompression check against the second data set. */
	check_return(nmsg_zbuf_inflate(zi, zlen, outbuf, &ulen, &ubuf) == nmsg_res_success);
	check_return(ulen == strlen((char *)tmpbuf));
	check(!memcmp(ubuf, tmpbuf, ulen));
	free(ubuf);

	nmsg_zbuf_destroy(&zd);
	check(zd == NULL);

	nmsg_zbuf_destroy(&zi);
	check(zi == NULL);

	l_return_test_status();
}

/* these pcap tests don't work, so comment out using ifdef */
#ifdef DISABLE_THESE_PCAP_TESTS

static int
test_pcap_dnsqr(void)
{
	nmsg_io_t io;
	nmsg_pcap_t pcap;
	pcap_t *phandle;
	nmsg_input_t input;
	nmsg_msgmod_t mod = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	io = nmsg_io_init();
	check_return(io != NULL);

	phandle = pcap_open_offline("/tmp/http.cap", errbuf);
	check_return(phandle != NULL);

	pcap = nmsg_pcap_input_open(phandle);
	check_return(pcap != NULL);

	/* A bad value should result in failure. */
	setenv("DNSQR_AUTH_ADDRS", "---garbage---", 1);
	mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_DNSQR_ID);
	check_return(mod != NULL);

	/* This is where the pcap parsing routine should fail. */
	input = nmsg_input_open_pcap(pcap, mod);
	check_return(input == NULL);

	nmsg_io_destroy(&io);
	check(io == NULL);

	l_return_test_status();
}

static int
test_pcap(void)
{
	nmsg_io_t io;
	nmsg_pcap_t pcap;
	pcap_t *phandle;
	nmsg_input_t input;
	nmsg_msgmod_t mod = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	io = nmsg_io_init();
	check_return(io != NULL);

	phandle = pcap_open_offline("/tmp/http.cap", errbuf);
	check_return(phandle != NULL);

	pcap = nmsg_pcap_input_open(phandle);
	check_return(pcap != NULL);

	mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_HTTP_ID);
	check_return(mod != NULL);

	input = nmsg_input_open_pcap(pcap, mod);
	check_return(input != NULL);

	nmsg_pcap_input_set_raw(pcap, true);

#define BPF_FILTER_STRING	"tcp dst port 80 or tcp src port 80"
	struct timespec ts;
	struct pcap_pkthdr *pphdr;
	const uint8_t *pkdata;

	check_return(nmsg_pcap_input_setfilter_raw(pcap, BPF_FILTER_STRING) == nmsg_res_success);
//	check_return(nmsg_pcap_input_setfilter(pcap, BPF_FILTER_STRING) == nmsg_res_success);
	check_return(nmsg_io_add_input(io, input, NULL) == nmsg_res_success);

for(size_t xxx = 0; xxx < 25; xxx++) {
	struct nmsg_ipdg ni;

	memset(&ni, 0, sizeof(ni));
	memset(&ts, 0, sizeof(ts));
	check_return(nmsg_pcap_input_read_raw(pcap, &pphdr, &pkdata, &ts) == nmsg_res_success);
//fprintf(stderr, "wow: %u\n", pphdr->caplen);
}
/*	fprintf(stderr, "hmm: %d\n", nmsg_pcap_input_read(pcap, &ni, &ts));
fprintf(stderr, "hmm: %d\n", nmsg_pcap_input_read(pcap, &ni, &ts));
}
	fprintf(stderr, "ok: proto = %d / %u [%s]\n", ni.proto_network, ni.len_payload, ni.payload);
	fprintf(stderr, "t: %u, n: %u\n", ni.len_transport, ni.len_network);
*/
//	fprintf(stderr, "HMM: %d\n", nmsg_pcap_filter(pcap, pkdata, pphdr->caplen));


//	fprintf(stderr, "snaplen: %d\n", nmsg_pcap_snapshot(pcap));
	fprintf(stderr, "datalink: %d\n", nmsg_pcap_get_datalink(pcap));

	check(nmsg_pcap_get_type(pcap) == nmsg_pcap_type_file);

#define BPF_NO_MATCH		"icmp"
	/* Apply a BPF string we know will not match and verify it falls through. */
	check_return(nmsg_pcap_input_setfilter_raw(pcap, BPF_NO_MATCH) == nmsg_res_success);
	check_return(nmsg_pcap_input_read_raw(pcap, &pphdr, &pkdata, &ts) == nmsg_res_eof);

	nmsg_io_set_interval(io, 5);

	nmsg_io_breakloop(io);

//	check(nmsg_input_close(&input) == nmsg_res_success);
//	check(nmsg_pcap_input_close(&pcap) == nmsg_res_success);

	nmsg_io_destroy(&io);
	check(io == NULL);

	l_return_test_status();
}

#endif /* comment out the non-working pcap tests */

/* Test nmsg_asprintf() and nmsg_vasprintf(). */
static int
test_printf(void)
{
	char *pbuf = NULL;

	TEST_FMT(&pbuf, 11, "testing 123", NULL);
	TEST_FMT(&pbuf, 12, "testing %d", 1234);
	TEST_FMT(&pbuf, 15, "testing %.7d", 1234);
	TEST_FMT(&pbuf, 12, "Hello, %s", "world");

	l_return_test_status();
}

/* Test msgmod lookups by name and msgtype; also convert pres data to payload. */
static int
test_msgmod(void)
{
	nmsg_msgmod_t mod1, mod2;
	void *clos;
	uint8_t *pbuf = NULL;
	size_t psz, i, max_i;

	/* Sanity checks resolving some basic and fake vendor IDs and message types */
	check(nmsg_msgmod_vname_to_vid("base") == NMSG_VENDOR_BASE_ID);
	check(nmsg_msgmod_get_max_vid() >= NMSG_VENDOR_BASE_ID);
	check(nmsg_msgmod_get_max_msgtype(NMSG_VENDOR_BASE_ID) == NMSG_VENDOR_BASE_DNSOBS_ID);
	check(!strcasecmp("base", nmsg_msgmod_vid_to_vname(NMSG_VENDOR_BASE_ID)));
	check(!strcasecmp("dnsqr", nmsg_msgmod_msgtype_to_mname(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_DNSQR_ID)));
	check(nmsg_msgmod_mname_to_msgtype(NMSG_VENDOR_BASE_ID, "pkt") == NMSG_VENDOR_BASE_PKT_ID);

	mod1 = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_HTTP_ID);
	check(mod1 != NULL);

	mod2 = nmsg_msgmod_lookup_byname("base", "http");
	check(mod2 != NULL);
	check(mod1 == mod2);

	mod2 = nmsg_msgmod_lookup_byname("base", "dnsqr");
	check_return(mod2 != NULL);
	check(mod1 != mod2);

	check_return(nmsg_msgmod_init(mod2, &clos) == nmsg_res_success);

	/* Attempt to convert presentation data to payload. */
	const char *nmsg_pres[] = {
		"type: UDP_QUERY_RESPONSE\n",
		"query_ip: 149.56.229.180\n",
		"response_ip: 136.161.101.66\n",
		"proto: 17\n",
		"query_port: 9726\n",
		"response_port: 53\n",
		"id: 10236\n",
		"qclass: 1\n",
		"qtype: 28\n",
		/* This last one should yield an error. */
		"qtype: AAA\n"
	};

	/* Holds the sizes that should be returned. */
	const size_t nmsg_pres_psz[] = { 14, 18, 18, 14, 15, 14, 15, 16, 16, 0 };
	max_i = sizeof(nmsg_pres) / sizeof(nmsg_pres[0]);

	for (i = 0; i < max_i; i++) {

		if (i < (max_i - 1)) {
			check(nmsg_msgmod_pres_to_payload(mod2, clos, nmsg_pres[i]) == nmsg_res_success);
			check(nmsg_msgmod_pres_to_payload_finalize(mod2, clos, &pbuf, &psz) == nmsg_res_success);
			check(pbuf != NULL);
			check(psz == nmsg_pres_psz[i]);

			if (pbuf)
				free(pbuf);

		} else {
			check(nmsg_msgmod_pres_to_payload(mod2, clos, nmsg_pres[i]) != nmsg_res_success);
		}

	}

	check(nmsg_msgmod_fini(mod2, &clos) == nmsg_res_success);
	check(clos == NULL);

	l_return_test_status();
}

/* Test the filter module subsystem against a message, using our sample module */
static int
test_fltmod(void)
{
	nmsg_fltmod_t fm;
	nmsg_message_t m;
	const char *mod_path = "./fltmod/.libs/nmsg_flt1_sample.so";
	const char *sample_param = "count=2";
	void *td = NULL;
	nmsg_filter_message_verdict v1, v2;

	/*
	 * 'param' should be a \0 terminated C string containing 'len_param'
	 * bytes of data, including the terminating \0.
	 */
	fm = nmsg_fltmod_init(mod_path, sample_param, strlen(sample_param) + 1);
	check_return(fm != NULL);

	check_return(nmsg_fltmod_thread_init(fm, &td) == nmsg_res_success);
	check_return(td != NULL);

	#define TEST_JSON_1     "{\"time\":\"2018-02-22 17:52:15.931822061\",\"vname\":\"base\",\"mname\":\"packet\",\"source\":\"a1ba02cf\",\"message\":{\"payload_type\": \"IP\", \"payload\":\"52.193.120.134\"}}"
	check_return(nmsg_message_from_json(TEST_JSON_1, &m) == nmsg_res_success);

	/* * With the sample module we always expect to see an alternation between results. */
	check_return(nmsg_fltmod_filter_message(fm, &m, td, &v1) == nmsg_res_success);
	check_return(nmsg_fltmod_filter_message(fm, &m, td, &v2) == nmsg_res_success);
	nmsg_message_destroy(&m);
	check(v1 != v2);
	check(v1 == nmsg_filter_message_verdict_DECLINED || v1 == nmsg_filter_message_verdict_DROP);
	check(v2 == nmsg_filter_message_verdict_DECLINED || v2 == nmsg_filter_message_verdict_DROP);

	check(nmsg_fltmod_thread_fini(fm, td) == nmsg_res_success);

	nmsg_fltmod_destroy(&fm);
	check(fm == NULL);

	l_return_test_status();
}

static void *cb_token = (void *)0xdeadbeef;
static int read_cb_success = 0, write_cb_success = 0;

static nmsg_res
test_read_callback(nmsg_message_t *msg, void *user)
{
//	assert(msg != NULL);
//	assert(user == cb_token);

//	read_cb_success = 1;
	read_cb_success = ((msg != NULL) && (user == cb_token));

	return nmsg_res_success;
}

static void
test_write_callback(nmsg_message_t msg, void *user)
{
//	assert(msg != NULL);
//	assert(user == cb_token);

//	write_cb_success = 1;
	write_cb_success = ((msg != NULL) && (user == cb_token));

	return;
}

/* Test write callbacks for nmsg outputs and read callbacks for nmsg inputs. */
static int
test_callbacks(void)
{
	nmsg_msgmod_t mm;
	nmsg_output_t o;
	nmsg_input_t i;
	nmsg_message_t m;

	i = nmsg_input_open_callback(test_read_callback, cb_token);
	check_return(i != NULL);

	/* A successful read and callback trigger sets read_cb_success */
	check(nmsg_input_read(i, &m) == nmsg_res_success);
	check(read_cb_success != 0);

	o = nmsg_output_open_callback(test_write_callback, cb_token);
	check_return(o != NULL);

	/* For output test we must craft a message first. */
	mm = nmsg_msgmod_lookup_byname("base", "packet");
	check_return(mm != NULL);

	m = nmsg_message_init(mm);
	check_return(m != NULL);

	/* A successful write and callback trigger sets write_cb_success */
	check(nmsg_output_write(o, m) == nmsg_res_success);
	check(write_cb_success != 0);

	nmsg_message_destroy(&m);
	check(nmsg_input_close(&i) == nmsg_res_success);
	check(nmsg_output_close(&o) == nmsg_res_success);

	l_return_test_status();
}

/* Test nmsg_set_autoclose() function. */
static int
test_autoclose(void)
{
	nmsg_input_t i;
	int fd;

	nmsg_set_autoclose(false);
	fd = open("/dev/null", O_RDWR);
	check_return(fd != -1);

	i = nmsg_input_open_file(fd);
	check_return(i != NULL);

	check(nmsg_input_close(&i) == nmsg_res_success);
	/* With no autoclose, our manual to close() should succeed. */
	check(close(fd) == 0);

	nmsg_set_autoclose(true);
	fd = open("/dev/null", O_RDWR);
	check_return(fd != -1);

	i = nmsg_input_open_file(fd);
	check_return(i != NULL);

	check(nmsg_input_close(&i) == nmsg_res_success);
	check(close(fd) == -1);
	/* But with it on, it should fail as it's already done for us. */
	check(errno == EBADF);

	l_return_test_status();
}

static int
test_ipdg(void)
{
	l_return_test_status();
}

/* Misc: test nmsg_message_add_allocation(), nmsg_message_free_allocations(),
   nmsg_get_debug() and nmsg_set_debug(). */
static int
test_miscx(void)
{
	nmsg_message_t m;
	nmsg_msgmod_t mm;
	char *buf;
	int o_debug;

	mm = nmsg_msgmod_lookup_byname("base", "encode");
	check_return(mm != NULL);

	m = nmsg_message_init(mm);
	check_return(m != NULL);

	buf = malloc(32);
	check_abort(buf != NULL);

	check(nmsg_message_add_allocation(m, buf) == nmsg_res_success);
	nmsg_message_free_allocations(m);

	/* That wasn't much of a test but at least we didn't crash... */
	nmsg_message_destroy(&m);

	/* Make sure our attempts to set the debug level stick. */
	o_debug = nmsg_get_debug();
	nmsg_set_debug(999);
	check(nmsg_get_debug() == 999);
	nmsg_set_debug(o_debug);
	check(nmsg_get_debug() == o_debug);

	l_return_test_status();
}

/* Check various nmsg result codes and their description strings */
static int
test_res(void)
{
	check(!strcasecmp("success", nmsg_res_lookup(nmsg_res_success)));
	check(strstr(nmsg_res_lookup(nmsg_res_notimpl), "implement"));
	check(strstr(nmsg_res_lookup(nmsg_res_errno), "errno"));
	check(strstr(nmsg_res_lookup(nmsg_res_errno+1), "unknown"));

	l_return_test_status();
}

/* Test parsing of various host and sockspec strings with IPv4 and IPv6 addresses. */
static int
test_sock_parse(void)
{
	struct sockaddr *sa = NULL;
	struct sockaddr_in6 s_in6;
	struct sockaddr_in s_in;
	socklen_t sa_len;
	unsigned short port = 10000;
	unsigned char dstbuf[sizeof(struct in6_addr)];
	char *paddr = NULL;
	unsigned int pp_start, pp_end;
	int pfamily;

	/* Grab the data-friendly form of IPv6 local host for future reference */
	check_return(inet_pton(AF_INET6, "::1", dstbuf) != -1);

	/* Garbage address should fail. */
	check(nmsg_sock_parse(AF_INET, "sdhfskdfajsf", port, &s_in, NULL, &sa, &sa_len) != nmsg_res_success);

	/* Verify a valid IPv4 address. */
	check_return(nmsg_sock_parse(AF_INET, "127.0.0.1", port, &s_in, NULL, &sa, &sa_len) == nmsg_res_success);
	check(s_in.sin_family == AF_INET);
	check(s_in.sin_addr.s_addr == inet_addr("127.0.0.1"));
	check(s_in.sin_port == htons(port));
	check(sa != NULL);
	check(sa && (((struct sockaddr_in *)sa)->sin_family == AF_INET));
	check(sa && (((struct sockaddr_in *)sa)->sin_addr.s_addr == inet_addr("127.0.0.1")));
	check(sa && (((struct sockaddr_in *)sa)->sin_port == htons(port)));
	check(sa_len == sizeof(struct sockaddr_in));

	/* Then a valid IPv6 string. */
	sa = NULL;
	check_return(nmsg_sock_parse(AF_INET6, "::1", port, NULL, &s_in6, &sa, &sa_len) == nmsg_res_success);
	check(s_in6.sin6_family == AF_INET6);
	check(!memcmp(&s_in6.sin6_addr, dstbuf, sizeof(dstbuf)));
	check(s_in6.sin6_port == htons(port));
	check(sa != NULL);
	check(sa && (((struct sockaddr_in6 *)sa)->sin6_family == AF_INET6));
	check(sa && (!memcmp(&((struct sockaddr_in6 *)sa)->sin6_addr, dstbuf, sizeof(dstbuf))));
	check(sa && (((struct sockaddr_in6 *)sa)->sin6_port == htons(port)));
	check(sa_len == sizeof(struct sockaddr_in6));

	check(nmsg_sock_parse_sockspec("10.32.237.255..8437", &pfamily, &paddr, &pp_start, &pp_end) != nmsg_res_success);
	/* There is a bug in nmsg_sock_parse_sockspec() -- it might return allocated memory in "paddr" even if the call fails. */
	free(paddr); paddr = NULL;
	check(nmsg_sock_parse_sockspec("10.32.237.255/8437..abc", &pfamily, &paddr, &pp_start, &pp_end) != nmsg_res_success);
	free(paddr); paddr = NULL;

	/* Now verify a valid IPv4 sockspec. */
	check_return(nmsg_sock_parse_sockspec("10.32.237.255/8430..8437", &pfamily, &paddr, &pp_start, &pp_end) == nmsg_res_success);
	check(pfamily == AF_INET);
	check(pp_start == 8430);
	check(pp_end == 8437);
	check(paddr && (!strcmp(paddr, "10.32.237.255")));
	free(paddr);

	/* And lastly, a valid IPv6 sockspec. */
	paddr = NULL;
	check_return(nmsg_sock_parse_sockspec("fde4:8dba:82e1::1/8431..8438", &pfamily, &paddr, &pp_start, &pp_end) == nmsg_res_success);
	check(pfamily == AF_INET6);
	check(pp_start == 8431);
	check(pp_end == 8438);
	check(!strcmp(paddr, "fde4:8dba:82e1::1"));
	free(paddr);

	l_return_test_status();
}

#define START_TVSEC	5005
#define START_TVNSEC	123450000
#define START_DVAL	5005.12345

/* Test various timespec functionality: to/from double, add, subtract, get, sleep. */
static int
test_ts(void)
{
	struct timespec ts1, ts2, ts3;
	double d;
	double sleep_times[4] = { .05, .1, .3, 1 };
	size_t i;

	/* Start off with a few very basic time value operations */
	memset(&ts1, 0, sizeof(ts1));
	memset(&ts2, 0, sizeof(ts2));

	ts1.tv_sec = START_TVSEC;
	ts1.tv_nsec = START_TVNSEC;

	/* Does timespec convert to double properly? */
	d = nmsg_timespec_to_double(&ts1);
	check(d == START_DVAL);

	/* And does the double convert back properly? */
	nmsg_timespec_from_double(d, &ts2);
	check(!memcmp(&ts1, &ts2, sizeof(ts1)));

	/* Simple time addition test */
	nmsg_timespec_add(&ts1, &ts2);
	check(ts2.tv_sec == START_TVSEC * 2);
	check(ts2.tv_nsec == START_TVNSEC * 2);

	/* Simple time substraction test */
	memcpy(&ts3, &ts2, sizeof(ts3));
	memset(&ts1, 0, sizeof(ts1));
	ts1.tv_sec = 10;
	ts1.tv_nsec = 100000;

	nmsg_timespec_sub(&ts1, &ts2);
	check(ts2.tv_sec == ts3.tv_sec - ts1.tv_sec);
	check(ts2.tv_nsec == ts3.tv_nsec - ts1.tv_nsec);

	/*
	 * Try sleeping for a few specified intervals.
	 * Make sure that we sleep for at least the specified time,
	 * but also that we do not oversleep.
	 */
	for (i = 0; i < (sizeof(sleep_times) / sizeof(sleep_times[0])); i++) {
		d = sleep_times[i];
		nmsg_timespec_from_double(d, &ts3);
		nmsg_timespec_get(&ts1);
		nmsg_timespec_sleep(&ts3);
		nmsg_timespec_get(&ts2);
		nmsg_timespec_sub(&ts1, &ts2);

		check(nmsg_timespec_to_double(&ts2) >= d);
		check(nmsg_timespec_to_double(&ts2) <= (d + .05));
	}

	l_return_test_status();
}

/* Serialize a message-as-container with sequencing and send it across a fd/socket. */
static int
send_container_fd(int fd, nmsg_message_t m, bool set_seq, uint32_t seq, uint64_t seqid)
{
	nmsg_container_t c;
	uint8_t *buf;
	size_t bufsz;

	c = nmsg_container_init(8192);
	check_return(c != NULL);

	nmsg_container_set_sequence(c, set_seq);
	check_return(nmsg_container_add(c, m) == nmsg_res_success);
	check_return(nmsg_container_serialize(c, &buf, &bufsz, true, false, seq, seqid) == nmsg_res_success);

	check_return(write(fd, buf, bufsz) == (int)bufsz);

	free(buf);
	nmsg_container_destroy(&c);

	return 0;
}

/* Test setting and verification of container sequence numbers. */
static int
test_seq(void)
{
	nmsg_msgmod_t mm;
	nmsg_message_t m, mi;
	int sfds[2];
	size_t n = 0;

	mm = nmsg_msgmod_lookup_byname("base", "packet");
	check_return(mm != NULL);

	m = nmsg_message_init(mm);
	check_return(m != NULL);

	return_if_error(fill_message(m));

	/*
	 * Our loop has 3 passes:
	 * #1. (n==0) Sequences are NOT set on containers. But they are verified on input.
	 * #2. (n==1) Sequences are set on containers. They are also verified on input.
	 * #3. (n==2) Sequences are set on containers. But they are NOT verified on input.
	 */
	while (n < 3) {
		nmsg_input_t i;
		uint64_t cr, cd;

		check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, sfds) != -1);

		i = nmsg_input_open_sock(sfds[0]);
		check_return(i != NULL);

		/* Create and send a container with an initial seq no/id. */
		return_if_error(send_container_fd(sfds[1], m, n, 0, 12345));

		/* The first two tests have their sequences verified. */
		if (n <= 1) {
			check_return(nmsg_input_set_verify_seqsrc(i, true) == nmsg_res_success);
		} else {
			check_return(nmsg_input_set_verify_seqsrc(i, false) == nmsg_res_success);
		}

		check_return(nmsg_input_read(i, &mi) == nmsg_res_success);
		nmsg_message_destroy(&mi);

		/* Skip 8 seq. nos. If tracked, dropped += 8 */
		return_if_error(send_container_fd(sfds[1], m, n, 9, 12345));
		check_return(nmsg_input_read(i, &mi) == nmsg_res_success);
		nmsg_message_destroy(&mi);

		/* Skip back several seq. nos. No effect. */
		return_if_error(send_container_fd(sfds[1], m, n, 3, 12345));
		check_return(nmsg_input_read(i, &mi) == nmsg_res_success);
		nmsg_message_destroy(&mi);

		/* Skip forward 6 seq. nos. If tracked, dropped += 6 */
		return_if_error(send_container_fd(sfds[1], m, n, 10, 12345));
		check_return(nmsg_input_read(i, &mi) == nmsg_res_success);
		nmsg_message_destroy(&mi);

		/* We're not really skipping, since we change seq. ids. */
		return_if_error(send_container_fd(sfds[1], m, n, 6, 123456));
		check_return(nmsg_input_read(i, &mi) == nmsg_res_success);
		nmsg_message_destroy(&mi);

		check_return(nmsg_input_get_count_container_received(i, &cr) == nmsg_res_success);

		if (n <= 1) {
			check_return(nmsg_input_get_count_container_dropped(i, &cd) == nmsg_res_success);
		} else {
			check(nmsg_input_get_count_container_dropped(i, &cd) != nmsg_res_success);
			cd = 0;
		}

		/* We sent 5 total single payload containers. If tracked, a cumulative 14 errors. */
		check(cr == 5);

		if (n == 1) {
			check(cd == 14);
		} else {
			check(cd == 0);
		}

		check(nmsg_input_close(&i) == nmsg_res_success);
		close(sfds[1]);

		n++;
	}

	nmsg_message_destroy(&m);

	l_return_test_status();
}

/* Wait half a second and break an input loop. */
static void *
threaded_iloop_stop(void *arg)
{
	nmsg_input_t i = (nmsg_input_t)arg;

	usleep(500000);
	nmsg_input_breakloop(i);

	return NULL;
}

static void
iloop_callback(nmsg_message_t msg, void *user)
{
	(void)(msg);
	(void)(user);
	return;
}

/* Test preemption of nmsg_input_loop() by nmsg_input_breakloop() function. */
static int
test_break_iloop(void)
{
	nmsg_input_t i;
	nmsg_res r;
	int sfds[2];
	pthread_t p;

	check_return(socketpair(AF_LOCAL, SOCK_STREAM, 0, sfds) != -1);

	i = nmsg_input_open_sock(sfds[0]);
	check_return(i != NULL);

	check_abort(pthread_create(&p, NULL, threaded_iloop_stop, i) == 0);
	r = nmsg_input_loop(i, -1, iloop_callback, NULL);
	check(r == nmsg_res_success);

	check_abort(pthread_join(p, NULL) == 0);

	check(nmsg_input_close(&i) == nmsg_res_success);

	l_return_test_status();
}

static int
test_inet_ntop(void)
{
	char *addr4[] = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "20.0.0.20", NULL};
	char *taddr4[] = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "20.0.0.20", NULL};
	char *addr6[] = {"2001:db8::1234:5678", "2001:db8:3333:4444:5555:6666:1.2.3.4", "2001:db8::", "::",
					 "2001:db8:3333:4444:cccc:dddd:eeee:ffff", "2001:db8:3333:4444:5555:6666:7777:8888", NULL};
	char *taddr6[] = {"2001:db8::1234:5678", "2001:db8:3333:4444:5555:6666:102:304", "2001:db8::", "::",
					  "2001:db8:3333:4444:cccc:dddd:eeee:ffff", "2001:db8:3333:4444:5555:6666:7777:8888", NULL};
	char ipv4[INET_ADDRSTRLEN];
	char ipv6[INET6_ADDRSTRLEN];
	char **paddr4 = addr4;
	char **ptaddr4 = taddr4;
	char **paddr6 = addr6;
	char **ptaddr6 = taddr6;

	while (*paddr4 != NULL) {
		struct sockaddr_in *sa;
		memset(ipv4, 0, sizeof(ipv4));

		check(inet_pton(AF_INET, *paddr4, &sa) == 1);
		check(fast_inet4_ntop(&sa, ipv4, INET_ADDRSTRLEN) != NULL);
		check(strcmp(*ptaddr4, ipv4) == 0);

		if (strcmp(*ptaddr4, ipv4) != 0) {
			printf("Error 2 [%s] != [%s]\n", ipv4, *paddr4);
		}

		++paddr4;
		++ptaddr4;
	}

	while (*paddr6 != NULL) {
		struct sockaddr_in6 *sa;

		memset(ipv6, 0, sizeof(ipv6));
		check(inet_pton(AF_INET6, *paddr6, &sa) == 1);
		check(fast_inet6_ntop(&sa, ipv6, INET6_ADDRSTRLEN) != NULL);
		check(strcmp(*ptaddr6, ipv6) == 0);

		if (strcmp(*ptaddr6, ipv6) != 0) {
			printf("Error 2 [%s] != [%s]\n", ipv6, *paddr6);
		}

		++paddr6;
		++ptaddr6;
	}


	l_return_test_status();
}

int
main(void)
{
	/* Need to be set prior to NMSG initialization. */
	check_return(setenv("NMSG_GRALIAS_FILE", SRCDIR "/tests/generic-tests/test.gralias", 1) == 0);
	check_return(setenv("NMSG_OPALIAS_FILE", SRCDIR "/tests/generic-tests/test.opalias", 1) == 0);

	check_abort(nmsg_init() == nmsg_res_success);

	check_explicit2_display_only(test_inet_ntop() == 0, "test-misc/ test_inet_ntop");
	check_explicit2_display_only(test_printf() == 0, "test-misc/ test_printf");
	check_explicit2_display_only(test_msgmod() == 0, "test-misc/ test_msgmod");
	check_explicit2_display_only(test_fltmod() == 0, "test-misc/ test_fltmod");
	check_explicit2_display_only(test_ipdg() == 0, "test-misc/ test_ipdg");
	check_explicit2_display_only(test_alias() == 0, "test-misc/ test_alias");
	check_explicit2_display_only(test_strbuf() == 0, "test-misc/ test_strbuf");
	check_explicit2_display_only(test_strbuf_json() == 0, "test-misc/ test_strbuf_json");
	check_explicit2_display_only(test_random() == 0, "test-misc/ test_random");
	check_explicit2_display_only(test_chan_alias() == 0, "test-misc/ test_chan_alias");
	check_explicit2_display_only(test_container() == 0, "test-misc/ test_container");
	check_explicit2_display_only(test_zbuf() == 0, "test-misc/ test_zbuf");
//	check_explicit2_display_only(test_pcap() == 0, "test-misc/ test_pcap");
//	check_explicit2_display_only(test_pcap_dnsqr() == 0, "test-misc/ test_pcap_dnsqr");
	check_explicit2_display_only(test_miscx() == 0, "test-misc/ test_miscx");
	check_explicit2_display_only(test_res() == 0, "test-misc/ test_res");
	check_explicit2_display_only(test_sock_parse() == 0, "test-misc/ test_sock_parse");
	check_explicit2_display_only(test_callbacks() == 0, "test-misc/ test_callbacks");
	check_explicit2_display_only(test_autoclose() == 0, "test-misc/ test_autoclose");
	check_explicit2_display_only(test_seq() == 0, "test-misc/ test_seq");
	check_explicit2_display_only(test_ts() == 0, "test-misc/ test_ts");
	check_explicit2_display_only(test_break_iloop() == 0, "test-misc/ test_break_iloop");

	g_check_test_status(false);
}
