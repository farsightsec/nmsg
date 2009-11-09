#include <alloca.h>
#include <stddef.h>

#include "msg/constants.h"
#include "msg/msg.h"

static void
print_data(const uint8_t *d, size_t len) {
        while (len-- != 0)
                fprintf(stderr, "%02x", *(d++));
        fprintf(stderr, "\n");
}

void
testfunc(wdns_message_t *m)
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
