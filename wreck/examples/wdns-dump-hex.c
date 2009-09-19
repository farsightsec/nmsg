/* wdns-dump-hex: read a packet from the command line */

#include "private.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "msg/msg.h"

#define advance(p, len, sz) do { (p) += (sz); (len) -= (sz); } while (0)
#define getu16(dst, src) do { memcpy(&(dst), src, 2); dst = ntohs(dst); } while (0)

void
packet_handler(uint8_t *rawmsg, size_t rawlen)
{
	wdns_message_t m;
	wdns_msg_status status;

	/* dns header */
	if (rawlen < 12) {
		VERBOSE("DNS header too short\n");
		return;
	}

	status = wdns_parse_message(rawmsg, rawmsg + rawlen, &m);
	if (status == wdns_msg_success) {
		wdns_print_message(stdout, &m);
		wdns_clear_message(&m);
	}

	VERBOSE("\n");
	return;
}

bool
hex_to_int(char hex, uint8_t *val)
{
	if (islower(hex))
		hex = toupper(hex);

	switch (hex) {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		*val = (hex - '0');
		return (true);
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
		*val = (hex - 55);
		return (true);
	default:
		printf("hex_to_int() failed\n");
		return (false);
	}
}

bool
decode_hex(const char *hex, uint8_t **raw, size_t *len)
{
	size_t hexlen = strlen(hex);
	uint8_t *p;

	if (hexlen == 0 || (hexlen % 2) != 0)
		return (false);

	*len = hexlen / 2;

	p = *raw = malloc(*len);
	if (*raw == NULL)
		return (false);

	while (hexlen != 0) {
		uint8_t val[2];

		if (!hex_to_int(*hex, &val[0]))
			goto err;
		hex++;
		if (!hex_to_int(*hex, &val[1]))
			goto err;
		hex++;

		*p = (val[0] << 4) | val[1];
		p++;

		hexlen -= 2;
	}

	return (true);
err:
	free(*raw);
	return (false);
}

int
main(int argc, char **argv)
{
	uint8_t *rawmsg;
	size_t rawlen;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <PKT>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (!decode_hex(argv[1], &rawmsg, &rawlen)) {
		fprintf(stderr, "Error: unable to decode hex\n");
		return (EXIT_FAILURE);
	}

	packet_handler(rawmsg, rawlen);

	free(rawmsg);

	return (EXIT_SUCCESS);
}
