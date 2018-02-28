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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "nmsg.h"
#include "nmsg/asprintf.h"
#include "nmsg/alias.h"
#include "nmsg/chalias.h"
#include "nmsg/container.h"
#include "nmsg/msgmod.h"
#include "nmsg/vendors.h"
#include "nmsg/base/defs.h"
#include "nmsg/sie/defs.h"

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
	assert(!strcmp("FSI", nmsg_alias_by_key(nmsg_alias_operator, 1)));
	assert(!strcmp("trafficconverter", nmsg_alias_by_key(nmsg_alias_group, 3)));
	assert(nmsg_alias_by_value(nmsg_alias_operator, "FSI") == 1);

	return 0;
}

static int
test_chan_alias(void)
{

	char **aliases;

	assert(nmsg_chalias_lookup("ch204", &aliases) > 0);
	nmsg_chalias_free(&aliases);

	return 0;
}

static int
test_strbuf(void)
{
	struct nmsg_strbuf *sb;

	sb = nmsg_strbuf_init();
	assert(sb != NULL);

	assert(nmsg_strbuf_append(sb, "%s %.4lx", "hello", 0x666) == nmsg_res_success);
	assert(nmsg_strbuf_len(sb) == 10);
	assert(!strcmp(sb->data, "hello 0666"));

	assert(nmsg_strbuf_reset(sb) == nmsg_res_success);
	assert(nmsg_strbuf_len(sb) == 0);

	nmsg_strbuf_destroy(&sb);

	return 0;
}

/* Test the random number generation functions */
static int
test_random(void)
{
	nmsg_random_t r;
	uint32_t r1, r2;
	uint8_t b1[16], b2[16];

	r = nmsg_random_init();
	assert(r != NULL);

	r1 = nmsg_random_uint32(r);
	r2 = nmsg_random_uint32(r);

	/* Well, this isn't necessarily true. But it's rather unlikely. */
	assert(r1 != r2);

	r2 = nmsg_random_uniform(r, 600);
	assert(r2 <= 600);

	memset(b1, 0, sizeof(b1));
	memset(b2, 0, sizeof(b2));
	assert(!memcmp(b1, b2, sizeof(b1)));
	nmsg_random_buf(r, b1, sizeof(b1));
	assert(memcmp(b1, b2, sizeof(b1)));

	nmsg_random_destroy(&r);

	return 0;
}

/* Fill a blank? message object with nonsense. */
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

/* Compare two nmsg message objects for equality. */
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
	uint8_t *tmpbuf1, *tmpbuf2;
	size_t i, tlen1, tlen2, m_len = 0;
	int failed = 0;

	/* This should fail. */
	c = nmsg_container_init(0);
	assert(c == NULL);

	/*
	 * This container should initialize properly and then eventually
	 * fail when it fills up because it is too small.
	 */
	c = nmsg_container_init(1024);

	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mm != NULL);

	m1 = nmsg_message_init(mm);
	assert(m1 != NULL);

	fill_message(m1);

	for (i = 0; i < 12; i++) {

		if (nmsg_container_add(c, m1) != nmsg_res_success) {
			failed = 1;
			break;
		}

	}

	assert(failed != 0);

	nmsg_container_destroy(&c);

	/*
	 * Now onto the main test.
	 * Create a container and verify the messages are added to it
	 * successfully and payloads adjusted accordingly.
	 */
	c = nmsg_container_init(NMSG_WBUFSZ_MAX);
	assert(c != NULL);

	m2 = nmsg_message_init(mm);
	assert(m2 != NULL);

	uint8_t *payload = malloc(4);
	memcpy(payload, "data", 4);
	m3 = nmsg_message_from_raw_payload(NMSG_VENDOR_BASE_ID, 0, payload, 4, NULL);
	assert(m3 != NULL);

	assert(nmsg_container_get_num_payloads(c) == 0);

	assert(nmsg_container_add(c, m1) == nmsg_res_success);

	/* Test compression. First add a message with an easily compressable field. */
#define REPEAT_FIELD	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	nmsg_message_set_field_by_idx(m2, 0, 0, (const uint8_t *)REPEAT_FIELD, strlen(REPEAT_FIELD));
	assert(nmsg_container_add(c, m2) == nmsg_res_success);
	assert(nmsg_container_get_num_payloads(c) == 2);

	assert(nmsg_container_add(c, m3) == nmsg_res_success);

	/* First try serialization without zlib compression. */
	assert(nmsg_container_serialize(c, &tmpbuf1, &tlen1, 1, 0, 1, 123) == nmsg_res_success);

	/* Then do it with compression. */
	assert(nmsg_container_serialize(c, &tmpbuf2, &tlen2, 1, 1, 1, 123) == nmsg_res_success);

	/* The second result (compressed serialized) should be smaller. */
	assert(tlen2 < tlen1);

	/* Try deserializing the uncompressed version. */
	assert(nmsg_container_deserialize(tmpbuf1, tlen1, &m_arr1, &m_len) == nmsg_res_success);
	assert(m_len == 3);
	free(tmpbuf1);

	/* Also verify the compressed variant. */
	assert(nmsg_container_deserialize(tmpbuf2, tlen2, &m_arr2, &m_len) == nmsg_res_success);
	assert(m_len == 3);
	free(tmpbuf2);

	/* Both deserialized messages should look the same. */
	assert(cmp_nmessages(m1, m_arr1[0]) == 0);
	assert(cmp_nmessages(m2, m_arr1[1]) == 0);

	assert(cmp_nmessages(m1, m_arr2[0]) == 0);
	assert(cmp_nmessages(m2, m_arr2[1]) == 0);

	/* Skip over the last nmsg because it should seem corrupt. */
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

/* Test zbuf inflation and deflation */
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
test_pcap_dnsqr(void)
{
	nmsg_io_t io;
	nmsg_pcap_t pcap;
	pcap_t *phandle;
	nmsg_input_t input;
	nmsg_msgmod_t mod = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	io = nmsg_io_init();
	assert(io != NULL);

	phandle = pcap_open_offline("/tmp/http.cap", errbuf);
	assert(phandle != NULL);

	pcap = nmsg_pcap_input_open(phandle);
	assert(pcap != NULL);

	/* A bad value should result in failure. */
	setenv("DNSQR_AUTH_ADDRS", "---garbage---", 1);
	mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID, NMSG_VENDOR_BASE_DNSQR_ID);
	assert(mod != NULL);

	/* This is where the pcap parsing routine should fail. */
	input = nmsg_input_open_pcap(pcap, mod);
	assert(input == NULL);

	nmsg_io_destroy(&io);
	assert(io == NULL);

	return 0;
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
	assert(io != NULL);

	phandle = pcap_open_offline("/tmp/http.cap", errbuf);
	assert(phandle != NULL);

	pcap = nmsg_pcap_input_open(phandle);
	assert(pcap != NULL);

	mod = nmsg_msgmod_lookup(NMSG_VENDOR_BASE_ID, 1);
//	mod = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mod != NULL);

	input = nmsg_input_open_pcap(pcap, mod);
	assert(input != NULL);

	nmsg_pcap_input_set_raw(pcap, true);

#define BPF_FILTER_STRING	"tcp dst port 80 or tcp src port 80"
	struct timespec ts;
	struct pcap_pkthdr *pphdr;
	const uint8_t *pkdata;

	assert(nmsg_pcap_input_setfilter_raw(pcap, BPF_FILTER_STRING) == nmsg_res_success);
//	assert(nmsg_pcap_input_setfilter(pcap, BPF_FILTER_STRING) == nmsg_res_success);
	assert(nmsg_io_add_input(io, input, NULL) == nmsg_res_success);

for(size_t xxx = 0; xxx < 25; xxx++) {
	struct nmsg_ipdg ni;

	memset(&ni, 0, sizeof(ni));
	memset(&ts, 0, sizeof(ts));
	assert(nmsg_pcap_input_read_raw(pcap, &pphdr, &pkdata, &ts) == nmsg_res_success);
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

	assert(nmsg_pcap_get_type(pcap) == nmsg_pcap_type_file);

#define BPF_NO_MATCH		"icmp"
	/* Apply a BPF string we know will not match and verify it falls through. */
	assert(nmsg_pcap_input_setfilter_raw(pcap, BPF_NO_MATCH) == nmsg_res_success);
	assert(nmsg_pcap_input_read_raw(pcap, &pphdr, &pkdata, &ts) == nmsg_res_eof);



	nmsg_io_set_interval(io, 5);

	nmsg_io_breakloop(io);

//	assert(nmsg_input_close(&input) == nmsg_res_success);
//	assert(nmsg_pcap_input_close(&pcap) == nmsg_res_success);

	nmsg_io_destroy(&io);
	assert(io == NULL);

	return 0;
}

/* Test nmsg_asprintf() and nmsg_vasprintf(). */
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

/* Test msgmod lookups by name and msgtype; also convert pres data to payload. */
static int
test_msgmod(void)
{
	nmsg_msgmod_t mod1, mod2;
	void *clos;
	uint8_t *pbuf;
	size_t psz;

	/* Sanity checks resolving some basic and fake vendor IDs and message types */
	assert(nmsg_msgmod_vname_to_vid("SIE") == NMSG_VENDOR_SIE_ID);
	assert(nmsg_msgmod_get_max_vid() >= NMSG_VENDOR_SIE_ID);
	assert(nmsg_msgmod_get_max_msgtype(NMSG_VENDOR_SIE_ID) == NMSG_VENDOR_SIE_DNSNX_ID);
	assert(!strcasecmp("sie", nmsg_msgmod_vid_to_vname(NMSG_VENDOR_SIE_ID)));
	assert(!strcasecmp("newdomain", nmsg_msgmod_msgtype_to_mname(NMSG_VENDOR_SIE_ID, NMSG_VENDOR_SIE_NEWDOMAIN_ID)));
	assert(nmsg_msgmod_mname_to_msgtype(NMSG_VENDOR_SIE_ID, "qr") == NMSG_VENDOR_SIE_QR_ID);

	mod1 = nmsg_msgmod_lookup(NMSG_VENDOR_SIE_ID, NMSG_VENDOR_SIE_NEWDOMAIN_ID);
	assert(mod1 != NULL);

	mod2 = nmsg_msgmod_lookup_byname("SIE", "newdomain");
	assert(mod2 != NULL);
	assert(mod1 == mod2);

	mod2 = nmsg_msgmod_lookup_byname("SIE", "reputation");
	assert(mod2 != NULL);
	assert(mod1 != mod2);

	assert(nmsg_msgmod_init(mod2, &clos) == nmsg_res_success);

	/* Attempt to convert presentation data to payload. */
	const char *nmsg_pres = //"[108] [2018-02-21 17:43:24.311901092] [2:5 SIE newdomain] [a1ba02cf] [] []\n"
		"domain: workable.com.\n"
		"time_seen: 2018-02-21 17:41:32\n"
		"bailiwick: workable.com.\n"
		"rrname: aspmx-bucketlist-dot-org.workable.com.\n"
		"rrclass: IN (1)\n"
		"rrtype: CNAME (5)\n"
		"rdata: qeoqj.x.incapdns.net.\n";

	assert(nmsg_msgmod_pres_to_payload(mod2, clos, nmsg_pres) == nmsg_res_success);
	assert(nmsg_msgmod_pres_to_payload_finalize(mod2, clos, &pbuf, &psz) == nmsg_res_success);
	assert(pbuf != NULL);
	assert(psz == 31);

	assert(nmsg_msgmod_fini(mod2, &clos) == nmsg_res_success);
	assert(clos == NULL);

	free(pbuf);

	return 0;
}

/* Test the filter module subsystem against a message, using our sample module */
static int
test_fltmod(void)
{
	nmsg_fltmod_t fm;
	const char *mod_path = "./fltmod/.libs/nmsg_flt1_sample.so";
	const char *sample_param = "count=2";
	void *td = NULL;
	nmsg_filter_message_verdict v1, v2;

	/*
	 * 'param' should be a \0 terminated C string containing 'len_param'
	 * bytes of data, including the terminating \0.
	 */
	fm = nmsg_fltmod_init(mod_path, sample_param, strlen(sample_param) + 1);
	assert(fm != NULL);

	assert(nmsg_fltmod_thread_init(fm, &td) == nmsg_res_success);
	assert(td != NULL);

	#define TEST_JSON_1     "{\"time\":\"2018-02-20 22:01:47.303896708\",\"vname\":\"SIE\",\"mname\":\"dnsdedupe\",\"source\":\"a1ba02cf\",\"message\":{\"type\":\"INSERTION\",\"count\":2,\"time_first\":\"2018-02-20 16:15:04\",\"time_last\":\"2018-02-20 19:04:42\",\"response_ip\":\"194.85.252.62\",\"bailiwick\":\"ru.\",\"rrname\":\"kinozal-chat.ru.\",\"rrclass\":\"IN\",\"rrtype\":\"NS\",\"rrttl\":345600,\"rdata\":[\"cdns1.ihc.ru.\",\"cdns2.ihc.ru.\"]}}"
	nmsg_message_t m;
	assert(nmsg_message_from_json(TEST_JSON_1, &m) == nmsg_res_success);

	/* * With the sample module we always expect to see an alternation between results. */
	assert(nmsg_fltmod_filter_message(fm, &m, td, &v1) == nmsg_res_success);
	assert(nmsg_fltmod_filter_message(fm, &m, td, &v2) == nmsg_res_success);
	assert(v1 != v2);
	assert(v1 == nmsg_filter_message_verdict_DECLINED || v1 == nmsg_filter_message_verdict_DROP);
	assert(v2 == nmsg_filter_message_verdict_DECLINED || v2 == nmsg_filter_message_verdict_DROP);

	assert(nmsg_fltmod_thread_fini(fm, td) == nmsg_res_success);

	nmsg_fltmod_destroy(&fm);
	assert(fm == NULL);

	return 0;
}

static void *cb_token = (void *)0xdeadbeef;
static int read_cb_success = 0, write_cb_success = 0;

static nmsg_res
test_read_callback(nmsg_message_t *msg, void *user)
{
	assert(msg != NULL);
	assert(user == cb_token);

	read_cb_success = 1;

	return nmsg_res_success;
}

static void
test_write_callback(nmsg_message_t msg, void *user)
{
	assert(msg != NULL);
	assert(user == cb_token);

	write_cb_success = 1;

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
	assert(i != NULL);

	/* A successful read and callback trigger sets read_cb_success */
	assert(nmsg_input_read(i, &m) == nmsg_res_success);
	assert(read_cb_success != 0);

	o = nmsg_output_open_callback(test_write_callback, cb_token);
	assert(o != NULL);

	/* For output test we must craft a message first. */ 
	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mm != NULL);

	m = nmsg_message_init(mm);
	assert(m != NULL);

	/* A successful write and callback trigger sets write_cb_success */
	assert(nmsg_output_write(o, m) == nmsg_res_success);
	assert(write_cb_success != 0);

	nmsg_message_destroy(&m);
	assert(nmsg_input_close(&i) == nmsg_res_success);
	assert(nmsg_output_close(&o) == nmsg_res_success);

	return 0;
}

/* Test nmsg_set_autoclose() function. */
static int
test_autoclose(void)
{
	nmsg_input_t i;
	int fd;

	nmsg_set_autoclose(false);
	fd = open("/dev/null", O_RDWR);
	assert(fd != -1);

	i = nmsg_input_open_file(fd);
	assert(i != NULL);

	assert(nmsg_input_close(&i) == nmsg_res_success);
	/* With no autoclose, our manual to close() should succeed. */
	assert(close(fd) == 0);

	nmsg_set_autoclose(true);
	fd = open("/dev/null", O_RDWR);
	assert(fd != -1);

	i = nmsg_input_open_file(fd);
	assert(i != NULL);

	assert(nmsg_input_close(&i) == nmsg_res_success);
	assert(close(fd) == -1);
	/* But with it on, it should fail as it's already done for us. */
	assert(errno == EBADF);

	return 0;
}

static int
test_ipdg(void)
{
	return 0;
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

	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mm != NULL);

	m = nmsg_message_init(mm);
	assert(m != NULL);

	buf = malloc(32);
	assert(buf != NULL);

	assert(nmsg_message_add_allocation(m, buf) == nmsg_res_success);
	nmsg_message_free_allocations(m);

	/* That wasn't much of a test but at least we didn't crash... */
	nmsg_message_destroy(&m);

	/* Make sure our attempts to set the debug level stick. */
	o_debug = nmsg_get_debug();
	nmsg_set_debug(999);
	assert(nmsg_get_debug() == 999);
	nmsg_set_debug(o_debug);
	assert(nmsg_get_debug() == o_debug);

	return 0;
}

/* Check various nmsg result codes and their description strings */
static int
test_res(void)
{
	assert(!strcasecmp("success", nmsg_res_lookup(nmsg_res_success)));
	assert(strstr(nmsg_res_lookup(nmsg_res_notimpl), "implement"));
	assert(strstr(nmsg_res_lookup(nmsg_res_errno), "errno"));
	assert(strstr(nmsg_res_lookup(nmsg_res_errno+1), "unknown"));

	return 0;
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
	char *paddr;
	unsigned int pp_start, pp_end;
	int pfamily;

	/* Grab the data-friendly form of IPv6 local host for future reference */
	assert(inet_pton(AF_INET6, "::1", dstbuf) != -1);

	/* Garbage address should fail. */
	assert(nmsg_sock_parse(AF_INET, "sdhfskdfajsf", port, &s_in, NULL, &sa, &sa_len) != nmsg_res_success);

	/* Verify a valid IPv4 address. */
	assert(nmsg_sock_parse(AF_INET, "127.0.0.1", port, &s_in, NULL, &sa, &sa_len) == nmsg_res_success);
	assert(s_in.sin_family == AF_INET);
	assert(s_in.sin_addr.s_addr == inet_addr("127.0.0.1"));
	assert(s_in.sin_port == htons(port));
	assert(sa != NULL);
	assert(((struct sockaddr_in *)sa)->sin_family == AF_INET);
	assert(((struct sockaddr_in *)sa)->sin_addr.s_addr == inet_addr("127.0.0.1"));
	assert(((struct sockaddr_in *)sa)->sin_port == htons(port));
	assert(sa_len == sizeof(struct sockaddr_in));

	/* Then a valid IPv6 string. */
	sa = NULL;
	assert(nmsg_sock_parse(AF_INET6, "::1", port, NULL, &s_in6, &sa, &sa_len) == nmsg_res_success);
	assert(s_in6.sin6_family == AF_INET6);
	assert(!memcmp(&s_in6.sin6_addr, dstbuf, sizeof(dstbuf)));
	assert(s_in6.sin6_port == htons(port));
	assert(sa != NULL);
	assert(((struct sockaddr_in6 *)sa)->sin6_family == AF_INET6);
	assert(!memcmp(&((struct sockaddr_in6 *)sa)->sin6_addr, dstbuf, sizeof(dstbuf)));
	assert(((struct sockaddr_in6 *)sa)->sin6_port == htons(port));
	assert(sa_len == sizeof(struct sockaddr_in6));

	assert(nmsg_sock_parse_sockspec("10.32.237.255..8437", &pfamily, &paddr, &pp_start, &pp_end) != nmsg_res_success);
	/* XXX: Why does the commented out line below work??? */
//	assert(nmsg_sock_parse_sockspec("10.32.237.255/8430..xyz", &pfamily, &paddr, &pp_start, &pp_end) != nmsg_res_success);

	/* Now verify a valid IPv4 sockspec. */
	assert(nmsg_sock_parse_sockspec("10.32.237.255/8430..8437", &pfamily, &paddr, &pp_start, &pp_end) == nmsg_res_success);
	assert(pfamily == AF_INET);
	assert(pp_start == 8430);
	assert(pp_end == 8437);
	assert(!strcmp(paddr, "10.32.237.255"));
	free(paddr);

	/* And lastly, a valid IPv6 sockspec. */
	assert(nmsg_sock_parse_sockspec("fde4:8dba:82e1::1/8431..8438", &pfamily, &paddr, &pp_start, &pp_end) == nmsg_res_success);
	assert(pfamily == AF_INET6);
	assert(pp_start == 8431);
	assert(pp_end == 8438);
	assert(!strcmp(paddr, "fde4:8dba:82e1::1"));
	free(paddr);

	return 0;
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
	assert(d == START_DVAL);

	/* And does the double convert back properly? */
	nmsg_timespec_from_double(d, &ts2);
	assert(!memcmp(&ts1, &ts2, sizeof(ts1)));

	/* Simple time addition test */
	nmsg_timespec_add(&ts1, &ts2);
	assert(ts2.tv_sec == START_TVSEC * 2);
	assert(ts2.tv_nsec == START_TVNSEC * 2);

	/* Simple time substraction test */
	memcpy(&ts3, &ts2, sizeof(ts3));
	memset(&ts1, 0, sizeof(ts1));
	ts1.tv_sec = 10;
	ts1.tv_nsec = 100000;

	nmsg_timespec_sub(&ts1, &ts2);
	assert(ts2.tv_sec == ts3.tv_sec - ts1.tv_sec);
	assert(ts2.tv_nsec == ts3.tv_nsec - ts1.tv_nsec);

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

		assert(nmsg_timespec_to_double(&ts2) >= d);
		assert(nmsg_timespec_to_double(&ts2) <= (d + .05));
	}

	return 0;
}

static int
test_seq(void)
{
/*	nmsg_msgmod_t mm;
	nmsg_input_t i;
	nmsg_container_t c;
	nmsg_message_t m, *mi;
	FILE *f;
	int fd;
	uint8_t *buf;
	size_t bufsz, n_mi;

	f = tmpfile();
	assert(f != NULL);

	fd = fileno(f);
	assert(fd != -1);

	c = nmsg_container_init(8192);
	assert(c != NULL);

	mm = nmsg_msgmod_lookup_byname("SIE", "dnsdedupe");
	assert(mm != NULL);

	m = nmsg_message_init(mm);
	assert(m != NULL);

	fill_message(m);

	nmsg_container_set_sequence(c, true);
	assert(nmsg_container_add(c, m) == nmsg_res_success);

	assert(nmsg_container_serialize(c, &buf, &bufsz, true, false, 0, 12345) == nmsg_res_success);

	i = nmsg_input_open_null();
        assert(i != NULL);

	assert(nmsg_input_set_verify_seqsrc(i, true) == nmsg_res_success);

	assert(nmsg_input_read_null(i, buf, bufsz, NULL, &mi, &n_mi) == nmsg_res_success);
	free(buf);

	nmsg_container_destroy(&c);
	c = nmsg_container_init(8192);
	assert(c != NULL);
	nmsg_container_set_sequence(c, true);
	assert(nmsg_container_add(c, m) == nmsg_res_success);
	assert(nmsg_container_serialize(c, &buf, &bufsz, true, false, 1, 12345) == nmsg_res_success);
	assert(nmsg_input_read_null(i, buf, bufsz, NULL, &mi, &n_mi) == nmsg_res_success);
	free(buf);

	nmsg_container_destroy(&c);
	c = nmsg_container_init(8192);
	assert(c != NULL);
	nmsg_container_set_sequence(c, true);
	assert(nmsg_container_add(c, m) == nmsg_res_success);
	assert(nmsg_container_serialize(c, &buf, &bufsz, true, false, 20, 12345) == nmsg_res_success);
	assert(nmsg_input_read_null(i, buf, bufsz, NULL, &mi, &n_mi) == nmsg_res_success);
	free(buf);

	nmsg_message_destroy(&m);
	nmsg_container_destroy(&c);
	assert(nmsg_input_close(&i) == nmsg_res_success);;

	fclose(f);*/

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
	ret |= check(test_msgmod(), "test-misc");
	ret |= check(test_fltmod(), "test-misc");
	ret |= check(test_ipdg(), "test-misc");
	ret |= check(test_alias(), "test-misc");
	ret |= check(test_strbuf(), "test-misc");
	ret |= check(test_random(), "test-misc");
	ret |= check(test_chan_alias(), "test-misc");
	ret |= check(test_container(), "test-misc");
	ret |= check(test_zbuf(), "test-misc");
	ret |= check(test_pcap(), "test-misc");
	ret |= check(test_pcap_dnsqr(), "test-misc");
	ret |= check(test_miscx(), "test-misc");
	ret |= check(test_res(), "test-misc");
	ret |= check(test_sock_parse(), "test-misc");
	ret |= check(test_callbacks(), "test-misc");
	ret |= check(test_autoclose(), "test-misc");
	ret |= check(test_seq(), "test-misc");
	ret |= check(test_ts(), "test-misc");

	if (ret)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
