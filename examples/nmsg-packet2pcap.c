/*
 * Copyright (c) 2010, 2013 by Farsight Security, Inc.
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nmsg.h>
#include <nmsg/base/defs.h>
#include <nmsg/base/packet.pb-c.h>
#include <pcap.h>

static int fd_in;
static nmsg_input_t input;
static pcap_t *output;
static pcap_dumper_t *output_dumper;

static void
dump_packet(const uint8_t *pkt, size_t len, struct timespec *ts) {
	struct pcap_pkthdr pkthdr;

	pkthdr.ts.tv_sec = ts->tv_sec;
	pkthdr.ts.tv_usec = ((double) ts->tv_nsec) / 1000.0;
	pkthdr.caplen = len;
	pkthdr.len = len;

	pcap_dump((u_char *) output_dumper, &pkthdr, pkt);
}

static void
callback(nmsg_message_t msg, void *user __attribute__((unused))) {
	const Nmsg__Base__Packet *packet;
	struct timespec ts;

	if (nmsg_message_get_vid(msg) == NMSG_VENDOR_BASE_ID &&
	    nmsg_message_get_msgtype(msg) == NMSG_VENDOR_BASE_PACKET_ID)
	{
		packet = (const Nmsg__Base__Packet *) nmsg_message_get_payload(msg);
		if (packet != NULL &&
		    packet->payload_type == NMSG__BASE__PACKET_TYPE__IP)
		{
			nmsg_message_get_time(msg, &ts);
			dump_packet(packet->payload.data, packet->payload.len, &ts);
		}
	}

	nmsg_message_destroy(&msg);
	return;
}

int
main(int argc, char **argv) {
	nmsg_res res;

	res = nmsg_init();
	if (res != nmsg_res_success) {
		fprintf(stderr, "nmsg_init() failed\n");
		return (EXIT_FAILURE);
	}

	/* initialize input and output */
	if (argc == 3) {
		/* nmsg input */
		if (strcmp(argv[1], "-") == 0) {
			fd_in = STDIN_FILENO;
		} else {
			fd_in = open(argv[1], O_RDONLY);
			if (fd_in == -1) {
				perror("open");
				return (EXIT_FAILURE);
			}
		}
		input = nmsg_input_open_file(fd_in);
		if (input == NULL) {
			fprintf(stderr, "nmsg_input_open_file() failed\n");
			return (EXIT_FAILURE);
		}

		/* pcap handles */
		output = pcap_open_dead(DLT_RAW, 65536);
		if (output == NULL) {
			fprintf(stderr, "pcap_open_dead() failed\n");
			return (EXIT_FAILURE);
		}
		output_dumper = pcap_dump_open(output, argv[2]);
		if (output_dumper == NULL) {
			fprintf(stderr, "pcap_dump_open() failed: %s\n",
				pcap_geterr(output));
			return (EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "usage: %s <NMSGfile> <PCAPfile>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	/* nmsg read loop */
	res = nmsg_input_loop(input, -1, callback, NULL);
	if (res != nmsg_res_success && res != nmsg_res_eof) {
		fprintf(stderr, "nmsg_input_loop() failed: %s\n", nmsg_res_lookup(res));
		return (EXIT_FAILURE);
	}

	/* clean up */
	nmsg_input_close(&input);
	pcap_dump_close(output_dumper);
	pcap_close(output);

	return (EXIT_SUCCESS);
}
