#include "private.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "msg/msg.h"

#include "hex.c"

extern bool loadfunc(uint8_t *data, size_t len);
extern bool testfunc(void);
extern void freefunc(void);

int
main(int argc, char **argv)
{
	size_t rawlen;
	uint8_t *rawdata;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <PKT>\n", argv[0]);
		return (EXIT_FAILURE);
	}

	if (!hex_decode(argv[1], &rawdata, &rawlen)) {
		fprintf(stderr, "Error: unable to decode hex\n");
		return (EXIT_FAILURE);
	}

	if (loadfunc(rawdata, rawlen)) {
		testfunc();
		freefunc();
	} else {
		free(rawdata);
		fprintf(stderr, "Error: load function failed\n");
		return (EXIT_FAILURE);
	}

	free(rawdata);

	return (EXIT_SUCCESS);
}
