#include "private.h"

void
wdns_reverse_name(const uint8_t *name, size_t len_name, uint8_t *rev_name) {
	const uint8_t *p;
	unsigned len;

	p = name;
	memset(rev_name, 0, len_name);
	rev_name += len_name - 1;

	while ((len = *p) != '\x00') {
		len += 1;
		rev_name -= len;
		memcpy(rev_name, p, len);
		p += len;
	}
}
