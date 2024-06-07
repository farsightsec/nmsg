/*
 * Copyright (c) 2024 DomainTools LLC
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


#include "errors.h"

#include "nmsg.h"
#include "private.h"
#include "nmsg/msgmod/transparent.h"

#define NAME	"test-private"

#define QUOTE(...)	#__VA_ARGS__

typedef struct {
	const char *field;
	size_t length;
	const char *response;
} answer_t;

typedef struct {
	const char *question;
	const answer_t *answer;
} task_t;

const char a2_response[] = {0x5b,0x94,0x84,0x20,0x00,0x01,0x00,0x03,0x00,0x04,0x00,0x01,0x04,0x78,0x78,0x78,0x78,0x04,0x78,0x78,0x78,0x78,0x05,0x78,0x78,0x78,0x78,0x78,0x03,0x78,0x78,0x78,0x03,0x78,0x78,0x78,0x0b,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x03,0x78,0x78,0x78,0x00,0x00,0x01,0x00,0x01,0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04,0x00,0x00,0x00,0x00,0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04,0x00,0x00,0x00,0x00,0xc0,0x0c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x04,0x00,0x00,0x00,0x00,0xc0,0x16,0x00,0x02,0x00,0x01,0x00,0x02,0xa3,0x00,0x00,0x17,0x07,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x09,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x03,0x78,0x78,0x78,0x00,0xc0,0x16,0x00,0x02,0x00,0x01,0x00,0x02,0xa3,0x00,0x00,0x19,0x07,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x09,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x02,0x78,0x78,0x02,0x78,0x78,0x00,0xc0,0x16,0x00,0x02,0x00,0x01,0x00,0x02,0xa3,0x00,0x00,0x13,0x06,0x78,0x78,0x78,0x78,0x78,0x78,0x09,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0xc0,0x30,0xc0,0x16,0x00,0x02,0x00,0x01,0x00,0x02,0xa3,0x00,0x00,0x16,0x06,0x78,0x78,0x78,0x78,0x78,0x78,0x09,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x78,0x03,0x78,0x78,0x78,0x00,0x00,0x00,0x29,0x10,0x00,0x00,0x00,0x80,0x00,0x00,0x00};
const char a3_query_packet[] = {0x45,0x00,0x00,0x47,0x3e,0xc8,0x00,0x00,0x01,0x11,0xad,0xc3,0xac,0x1e,0x40,0x01,0xe0,0x00,0x00,0xfb,0x14,0xe9,0x14,0xe9,0x00,0x33,0x5f,0x1d,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x0e,0x5f,0x6d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x5f,0x6d,0x63,0x63,0x04,0x5f,0x74,0x63,0x70,0x05,0x6c,0x6f,0x63,0x61,0x6c,0x00,0x00,0x0c,0x80,0x01};
const char a3_query[] = {0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x0e,0x5f,0x6d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x5f,0x6d,0x63,0x63,0x04,0x5f,0x74,0x63,0x70,0x05,0x6c,0x6f,0x63,0x61,0x6c,0x00,0x00,0x0c,0x80,0x01};
const char a3_query_time_sec[] = {0x8e,0x04,0x50,0x64,0x00,0x00,0x00,0x00};
const char a3_query_time_nsec[] = {0xc0,0xde,0x76,0x08};

const answer_t a1[] = {{"type", 7, "unknown"},
		       {"dstip", 9, "192.0.2.2"},
		       {"dstport", 2, "80"},
		       {"request", 6, "GET /\0"},
		       { NULL, 0, NULL}};

const answer_t a2[] = {{"time", 10, "1682087949"},
		       {"response_ip", 3, "::1"},
		       {"qname", 16, "xxx.xxx.xxx.xxx."},
		       {"qtype", 1, "A"},
		       {"qclass", 2, "IN"},
		       {"rcode", 7, "NOERROR"},
		       {"response", sizeof(a2_response), a2_response},
		       {"response_json", 615, QUOTE({"header":{"opcode":"QUERY","rcode":"NOERROR","id":23444,"flags":["qr","aa","ad"],"opt":{"edns":{"version":0,"flags":["do"],"udp":4096,"options":[]}}},"question":[{"qname":"xxxx.xxxx.xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","qclass":"IN","qtype":"A"}],"answer":[{"rrname":"xxxx.xxxx.xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","rrttl":60,"rrclass":"IN","rrtype":"A","rdata":["0.0.0.0","0.0.0.0","0.0.0.0"]}],"authority":[{"rrname":"xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","rrttl":172800,"rrclass":"IN","rrtype":"NS","rdata":["xxxxxxx.xxxxxxxxx.xxx.","xxxxxxx.xxxxxxxxx.xx.xx.","xxxxxx.xxxxxxxxx.xxx.","xxxxxx.xxxxxxxxx.xxx."]}],"additional":[]})},
		       {"query_zone", 16, "xxx.xxx.xxx.xxx."},
		       {"geoid", 1, "\x0"},
		       {"sensor_id", 1, "4"},
		       { NULL, 0, NULL}};

const answer_t a3[] = {{"type", 20, "UDP_UNANSWERED_QUERY"},
		       {"query_ip", 7, "0.0.0.0"},
		       {"response_ip", 7, "0.0.0.0"},
		       {"proto", 3, "UDP"},
		       {"query_port", 4, "5353"},
		       {"response_port", 4, "5353"},
		       {"id", 1, "0"},
		       {"qname", 26, "_microsoft_mcc._tcp.local."},
		       {"qclass", 10, "CLASS32769"},
		       {"qtype", 7, "TYPE149"},
		       {"query_packet", sizeof(a3_query_packet), a3_query_packet},
		       {"query_time_sec", sizeof(a3_query_time_sec), a3_query_time_sec},
		       {"query_time_nsec", sizeof(a3_query_time_nsec), a3_query_time_nsec},
		       {"response_packet", 0, "\0"},
		       {"response_time_sec", 0, "\0"},
		       {"response_time_nsec", 0, "\0"},
		       {"timeout", 21, "72.502578999999997222"},
		       {"query", sizeof(a3_query), a3_query},
		       {"query_json", 196, QUOTE({"header":{"opcode":"QUERY","rcode":"NOERROR","id":0,"flags":[]},"question":[{"qname":"_microsoft_mcc._tcp.local.","qclass":"CLASS32769","qtype":"PTR"}],"answer":[],"authority":[],"additional":[]})},
		       { NULL, 0, NULL}};

const task_t tasks[] = {{QUOTE({"time":"2018-02-20 22:01:47.303896708","vname":"base","mname":"http","source":"abcdef01","message":{"type":"unknown","dstip":"192.0.2.2","dstport":80,"request":"GET /"}}),
			a1},
			{QUOTE({"time":"2023-04-21 14:39:10.039412373","vname":"base","mname":"dnsobs","message":{"time":1682087949,"response_ip":"::1","qname":"xxx.xxx.xxx.xxx.","qtype":"A","qclass":"IN","rcode":"NOERROR","response":"W5SEIAABAAMABAABBHh4eHgEeHh4eAV4eHh4eAN4eHgDeHh4C3h4eHh4eHh4eHh4A3h4eAAAAQABwAwAAQABAAAAPAAEAAAAAMAMAAEAAQAAADwABAAAAADADAABAAEAAAA8AAQAAAAAwBYAAgABAAKjAAAXB3h4eHh4eHgJeHh4eHh4eHh4A3h4eADAFgACAAEAAqMAABkHeHh4eHh4eAl4eHh4eHh4eHgCeHgCeHgAwBYAAgABAAKjAAATBnh4eHh4eAl4eHh4eHh4eHjAMMAWAAIAAQACowAAFgZ4eHh4eHgJeHh4eHh4eHh4A3h4eAAAACkQAAAAgAAAAA==","response_json":{"header":{"opcode":"QUERY","rcode":"NOERROR","id":23444,"flags":["qr","aa","ad"],"opt":{"edns":{"version":0,"flags":["do"],"udp":4096,"options":[]}}},"question":[{"qname":"xxxx.xxxx.xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","qclass":"IN","qtype":"A"}],"answer":[{"rrname":"xxxx.xxxx.xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","rrttl":60,"rrclass":"IN","rrtype":"A","rdata":["0.0.0.0","0.0.0.0","0.0.0.0"]}],"authority":[{"rrname":"xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","rrttl":172800,"rrclass":"IN","rrtype":"NS","rdata":["xxxxxxx.xxxxxxxxx.xxx.","xxxxxxx.xxxxxxxxx.xx.xx.","xxxxxx.xxxxxxxxx.xxx.","xxxxxx.xxxxxxxxx.xxx."]}],"additional":[]},"query_zone":"xxx.xxx.xxx.xxx.","geoid":"AA==","sensor_id":"423a35c7"}}),
			 a2},
			{QUOTE({"time":"2023-05-01 18:27:26.142008000","vname":"base","mname":"dnsqr","message":{"type":"UDP_UNANSWERED_QUERY","query_ip":"0.0.0.0","response_ip":"0.0.0.0","proto":"UDP","query_port":5353,"response_port":5353,"id":0,"qname":"_microsoft_mcc._tcp.local.","qclass":"CLASS32769","qtype":"TYPE149","query_packet":["RQAARz7IAAABEa3DrB5AAeAAAPsU6RTpADNfHQAAAAAAAQAAAAAAAA5fbWljcm9zb2Z0X21jYwRfdGNwBWxvY2FsAAAMgAE="],"query_time_sec":[1682965646],"query_time_nsec":[142008000],"response_packet":[],"response_time_sec":[],"response_time_nsec":[],"timeout":72.502578999999997222,"query":"AAAAAAABAAAAAAAADl9taWNyb3NvZnRfbWNjBF90Y3AFbG9jYWwAAAyAAQ==","query_json":{"header":{"opcode":"QUERY","rcode":"NOERROR","id":0,"flags":[]},"question":[{"qname":"_microsoft_mcc._tcp.local.","qclass":"CLASS32769","qtype":"PTR"}],"answer":[],"authority":[],"additional":[]}}}),
			 a3},
			{NULL,NULL}};

static int
test_kafka_key(void) {
	nmsg_input_t i;
	nmsg_message_t m;
	FILE *f;
	int fd;
	const task_t *t;
	const answer_t *a;
	struct nmsg_strbuf_storage tbs;
	struct nmsg_strbuf *tb = _nmsg_strbuf_init(&tbs);

	/* Create test file */
	f = tmpfile();
	check_return(f != NULL);

	fd = fileno(f);
	check_return(fd != -1);

	t = tasks;
	while (t->question != NULL) {
		check_return(write(fd, t->question, strlen(t->question)) == (ssize_t) strlen(t->question));
		check_return(write(fd, "\n", 1) == 1);
		++t;
	}

	check_return(lseek(fd, SEEK_SET, 0) == 0);

	i = nmsg_input_open_json(fd);
	check_return(i != NULL);

	t = tasks;
	while (t->question != NULL) {
		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		a = t->answer;
		printf("Question [%s]\n",t->question);
		while (a->field != NULL) {
			check_return(_nmsg_message_payload_get_field_value_as_key(m, a->field, tb) == nmsg_res_success);
			printf("Key [%s] Expect [%s][%lu] - Result [%s][%lu]\n", a->field, a->response, a->length, tb->data, nmsg_strbuf_len(tb));
			check_return(memcmp(tb->data, a->response, a->length) == 0);
			check_return(nmsg_strbuf_len(tb) == a->length);
			nmsg_strbuf_reset(tb);
			++a;
		}
		nmsg_message_destroy(&m);
		++t;
	}

	_nmsg_strbuf_destroy(&tbs);
	fclose(f);

	l_return_test_status();
}

int
main(void)
{
	check_abort(nmsg_init() == nmsg_res_success);

	check_explicit2_display_only(test_kafka_key() == 0, "test-private / test_kafka_key");

	g_check_test_status(false);
}
