#include <alloca.h>
#include <stddef.h>

#include "msg/constants.h"
#include "msg/msg.h"

wdns_message_t m;

bool
loadfunc(uint8_t *data, size_t len)
{
	wdns_msg_status status;
	status = wdns_parse_message(&m, data, len);
	if (status != wdns_msg_success)
		return (false);
	return (true);
}

void
freefunc(void)
{
	wdns_clear_message(&m);
}


static void
print_data(const uint8_t *d, size_t len) {
        while (len-- != 0)
                fprintf(stderr, "%02x", *(d++));
        fprintf(stderr, "\n");
}

bool
testfunc(void)
{
	wdns_rrset_array_t *a;
	wdns_rrset_t *rrset;
	size_t sz;
	uint8_t *buf;

	for (size_t sec = WDNS_MSG_SEC_ANSWER; sec < WDNS_MSG_SEC_MAX; sec++) {
		a = &m.sections[sec];
		for (size_t n = 0; n < a->n_rrsets; n++) {
			rrset = &a->rrsets[n];
			wdns_serialize_rrset(rrset, NULL, &sz);
			buf = alloca(sz);
			wdns_serialize_rrset(rrset, buf, NULL);
			print_data(buf, sz);
		}
	}
	return (true);
}
