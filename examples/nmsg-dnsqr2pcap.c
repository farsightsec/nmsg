/*
 * Copyright (c) 2010 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nmsg.h>
#include <nmsg/isc/defs.h>
#include <nmsg/isc/dnsqr.pb-c.h>
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
	const Nmsg__Isc__DnsQR *dnsqr;
	size_t n;
	struct timespec ts;

	if (nmsg_message_get_vid(msg) != NMSG_VENDOR_ISC_ID)
		goto out;
	if (nmsg_message_get_msgtype(msg) != NMSG_VENDOR_ISC_DNSQR_ID)
		goto out;
	
	dnsqr = (const Nmsg__Isc__DnsQR *) nmsg_message_get_payload(msg);
	if (dnsqr == NULL)
		goto out;

	for (n = 0; n < dnsqr->n_query_packet; n++) {
		ts.tv_sec = dnsqr->query_time_sec[n];
		ts.tv_nsec = dnsqr->query_time_nsec[n];
		dump_packet(dnsqr->query_packet[n].data,
			    dnsqr->query_packet[n].len,
			    &ts);
	}

	for (n = 0; n < dnsqr->n_response_packet; n++) {
		ts.tv_sec = dnsqr->response_time_sec[n];
		ts.tv_nsec = dnsqr->response_time_nsec[n];
		dump_packet(dnsqr->response_packet[n].data,
			    dnsqr->response_packet[n].len,
			    &ts);
	}

out:
	nmsg_message_destroy(&msg);
	return;
}

int
main(int argc, char **argv) {
	nmsg_res res;

	assert(nmsg_init() == nmsg_res_success);

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
