#include "private.h"

wdns_msg_status
wdns_left_chop(wdns_name_t *name, wdns_name_t *chop)
{
	uint8_t oclen;

	oclen = name->data[0];

	if (oclen == 0 && name->len == 1) {
		chop->len = 1;
		chop->data = name->data;
		return (wdns_msg_success);
	}

	if (oclen > name->len - 1)
		return (wdns_msg_err_name_overflow);

	chop->len = name->len - oclen - 1;
	chop->data = name->data + oclen + 1;
	return (wdns_msg_success);
}
