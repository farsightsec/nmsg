/* wdns-deserialize-rrset */

#include "private.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "msg/msg.h"
#include "msg/constants.h"

#include "hex.h"

int
main(int argc, char **argv)
{
	size_t rawlen;
	uint8_t *rawmsg;
	wdns_msg_status status;
	wdns_rrset_t rrset;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <RRSET>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (!hex_decode(argv[1], &rawmsg, &rawlen)) {
		fprintf(stderr, "Error: unable to decode hex\n");
		return (EXIT_FAILURE);
	}

	status = wdns_deserialize_rrset(rawmsg, rawlen, &rrset);

	if (status == wdns_msg_success) {
		wdns_print_rrset(stdout, &rrset, WDNS_MSG_SEC_ANSWER);
		wdns_clear_rrset(&rrset);
	} else {
		free(rawmsg);
		fprintf(stderr, "Error: wdns_deserialize_rrset() returned %u\n",
			status);
		return (EXIT_FAILURE);
	}

	free(rawmsg);

	return (EXIT_SUCCESS);
}
