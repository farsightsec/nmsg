#include "private.h"

#include <wdns.h>

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

bool
testfunc(void)
{
	wdns_print_message(stdout, &m);
	return (true);
}
