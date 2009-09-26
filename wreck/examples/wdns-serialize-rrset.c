/* wdns-serialize-rrset: read a packet from the command line and output
 * serialized rrsets */

#include "private.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "msg/constants.h"
#include "msg/msg.h"

#include "hex.h"

static void
print_data(const uint8_t *d, size_t len) {
        while (len-- != 0)
                fprintf(stderr, "%02x", *(d++));
        fprintf(stderr, "\n");
}

static void
serialize_rrsets(wdns_message_t *m)
{
	wdns_rrset_array_t *a;
	wdns_rrset_t *rrset;
	size_t sz;
	uint8_t *buf;

	for (size_t sec = WDNS_MSG_SEC_ANSWER; sec < WDNS_MSG_SEC_MAX; sec++) {
		a = &m->sections[sec];
		for (size_t n = 0; n < a->n_rrsets; n++) {
			rrset = &a->rrsets[n];
			wdns_serialize_rrset(rrset, NULL, &sz);
			buf = alloca(sz);
			wdns_serialize_rrset(rrset, buf, NULL);
			print_data(buf, sz);
		}
	}
}

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
		serialize_rrsets(&m);
		wdns_clear_message(&m);
	} else {
		free(rawmsg);
		fprintf(stderr, "Error: wdns_parse_message() returned %u\n", status);
		return (EXIT_FAILURE);
	}

	free(rawmsg);

	return (EXIT_SUCCESS);
}
