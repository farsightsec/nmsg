/* wdns-dump-hex: read a packet from the command line */

#include "private.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "msg/msg.h"

#include "hex.h"

int
main(int argc, char **argv)
{
	size_t rawlen;
	uint8_t *rawmsg;
	wdns_message_t m;
	wdns_msg_status status;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <PKT>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (!hex_decode(argv[1], &rawmsg, &rawlen)) {
		fprintf(stderr, "Error: unable to decode hex\n");
		return (EXIT_FAILURE);
	}

	status = wdns_parse_message(rawmsg, rawmsg + rawlen, &m);
	if (status == wdns_msg_success) {
		wdns_print_message(stdout, &m);
		wdns_clear_message(&m);
	} else {
		free(rawmsg);
		fprintf(stderr, "Error: wdns_parse_message() returned %u\n", status);
		return (EXIT_FAILURE);
	}

	free(rawmsg);

	return (EXIT_SUCCESS);
}
