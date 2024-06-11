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

/* This module contains unit tests that target the private NMSG library functions */

#define QUOTE(...)	#__VA_ARGS__

typedef struct {
	const char *field;
	size_t length;
	const char *response;
} answer_t;

typedef struct {
	const char *payload;
	const answer_t *answer;
} task_t;


#define A1_MESSAGE	QUOTE({"time":"2018-02-20 22:01:47.303896708","vname":"base","mname":"http","source":"abcdef01","message":{"type":"unknown","dstip":"192.0.2.2","dstport":80,"request":"GET /"}})

/* Type base:http */
const answer_t a1[] = {
	{ "type", 7, "unknown" },	/* enum */
	{ "dstip", 9, "192.0.2.2" },	/* bytes | nmsg_msgmod_ft_ip */
	{ "dstport", 2, "80" },		/* uint32 */
	{ "request", 5, "GET /"},	/* bytes | nmsg_msgmod_ft_mlstring */
	{ NULL, 0, NULL }
};

#define A2_MESSAGE	QUOTE({"time":"2023-04-21 14:39:10.039412373","vname":"base","mname":"dnsobs","message":{"time":1682087949,"response_ip":"::1","qname":"xxx.xxx.xxx.xxx.","qtype":"A","qclass":"IN","rcode":"NOERROR","response":"W5SEIAABAAMABAABBHh4eHgEeHh4eAV4eHh4eAN4eHgDeHh4C3h4eHh4eHh4eHh4A3h4eAAAAQABwAwAAQABAAAAPAAEAAAAAMAMAAEAAQAAADwABAAAAADADAABAAEAAAA8AAQAAAAAwBYAAgABAAKjAAAXB3h4eHh4eHgJeHh4eHh4eHh4A3h4eADAFgACAAEAAqMAABkHeHh4eHh4eAl4eHh4eHh4eHgCeHgCeHgAwBYAAgABAAKjAAATBnh4eHh4eAl4eHh4eHh4eHjAMMAWAAIAAQACowAAFgZ4eHh4eHgJeHh4eHh4eHh4A3h4eAAAACkQAAAAgAAAAA==","response_json":{"header":{"opcode":"QUERY","rcode":"NOERROR","id":23444,"flags":["qr","aa","ad"],"opt":{"edns":{"version":0,"flags":["do"],"udp":4096,"options":[]}}},"question":[{"qname":"xxxx.xxxx.xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","qclass":"IN","qtype":"A"}],"answer":[{"rrname":"xxxx.xxxx.xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","rrttl":60,"rrclass":"IN","rrtype":"A","rdata":["0.0.0.0","0.0.0.0","0.0.0.0"]}],"authority":[{"rrname":"xxxxx.xxx.xxx.xxxxxxxxxxx.xxx.","rrttl":172800,"rrclass":"IN","rrtype":"NS","rdata":["xxxxxxx.xxxxxxxxx.xxx.","xxxxxxx.xxxxxxxxx.xx.xx.","xxxxxx.xxxxxxxxx.xxx.","xxxxxx.xxxxxxxxx.xxx."]}],"additional":[]},"query_zone":"xxx.xxx.xxx.xxx.","geoid":"ESIzRA==","sensor_id":"423a35c7"}})

#define A3_MESSAGE	QUOTE({"time":"2023-05-01 18:27:26.142008000","vname":"base","mname":"dnsqr","message":{"type":"UDP_UNANSWERED_QUERY","query_ip":"0.0.0.0","response_ip":"0.0.0.0","proto":"UDP","query_port":5353,"response_port":5353,"id":0,"qname":"_microsoft_mcc._tcp.local.","qclass":"CLASS32769","qtype":"TYPE149","query_packet":["RQAARz7IAAABEa3DrB5AAeAAAPsU6RTpADNfHQAAAAAAAQAAAAAAAA5fbWljcm9zb2Z0X21jYwRfdGNwBWxvY2FsAAAMgAE="],"query_time_sec":[1682965646],"query_time_nsec":[142008000],"response_packet":[],"response_time_sec":[],"response_time_nsec":[],"timeout":72.502578999999997222,"query":"AAAAAAABAAAAAAAADl9taWNyb3NvZnRfbWNjBF90Y3AFbG9jYWwAAAyAAQ==","query_json":{"header":{"opcode":"QUERY","rcode":"NOERROR","id":0,"flags":[]},"question":[{"qname":"_microsoft_mcc._tcp.local.","qclass":"CLASS32769","qtype":"PTR"}],"answer":[],"authority":[],"additional":[]}}})

/* Type base:dnsobs */
const answer_t a2[] = {
	{ "time", 10, "1682087949" },	/* uint64 */
	{ "response_ip", 3, "::1" },	/* bytes | nmsg_msgmod_ft_ip */
	{ "qname", 16, "xxx.xxx.xxx.xxx." },	/* bytes | dns_name_format */
	{ "qtype", 1, "A" },		/* uint32 | dns_type_format */
	{ "qclass", 2, "IN" },		/* uint32 | dns_class_format */
	{ "rcode", 7, "NOERROR" },	/* uint32 i| dnsqr_rcode_format */
	{ "query_zone", 16, "xxx.xxx.xxx.xxx." },	/* bytes | dns_name_format */
	{ "geoid", 4, "\x11\x22\x33\x44" },		/* bytes */
	{ "sensor_id", 1, "4" },	/* fixed32 | dnsobs_sid_format */
	{ NULL, 0, NULL }
};

/* Type base:dnsqr */
const answer_t a3[] = {
	{ "type", 20, "UDP_UNANSWERED_QUERY" },	/* enum */
	{ "query_ip", 7, "0.0.0.0" },		/* bytes | nmsg_msgmod_ft_ip */
	{ "response_ip", 7, "0.0.0.0" },	/* bytes | nmsg_msgmod_ft_ip */
	{ "proto", 3, "UDP" },		/* uint32 | dnsqr_proto_format */
	{ "query_port", 4, "5353" },	/* uint32 */
	{ "response_port", 4, "5353" },	/* uint32 */
	{ "id", 1, "0" },		/* uint32 */
	{ "qname", 26, "_microsoft_mcc._tcp.local." },	/* bytes | dns_name_format */
	{ "qclass", 10, "CLASS32769" },	/* uint32 | dns_class_format */
	{ "qtype", 7, "TYPE149" },	/* uint32 | dns_type_format */
	{ "query_time_sec", 8, "\x8e\x04\x50\x64\x00\x00\x00\x00" },	/* int64 */
	{ "query_time_nsec", 4, "\xc0\xde\x76\x08" },	/* sfixed32: 142008000 */
	{ "response_time_sec", 0, "\0" },	/* int64 */
	{ "response_time_nsec", 0, "\0" },	/* sfixed32 */
	{ "timeout", 21, "72.502578999999997222" },	/* double */
	{ NULL, 0, NULL }
};

const task_t tasks[] = {
	{ A1_MESSAGE, a1 },
	{ A2_MESSAGE, a2 },
	{ A3_MESSAGE, a3 },
	{NULL,NULL}
};

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
	while (t->payload != NULL) {
		check_return(write(fd, t->payload, strlen(t->payload)) == (ssize_t) strlen(t->payload));
		check_return(write(fd, "\n", 1) == 1);
		++t;
	}

	check_return(lseek(fd, SEEK_SET, 0) == 0);

	i = nmsg_input_open_json(fd);
	check_return(i != NULL);

	t = tasks;
	while (t->payload != NULL) {
		check_return(nmsg_input_read(i, &m) == nmsg_res_success);
		a = t->answer;
		printf("Question [%s]\n",t->payload);
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
