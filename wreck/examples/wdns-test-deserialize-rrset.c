#include "private.h"

#include <wdns.h>

wdns_rrset_t rrset;

bool
loadfunc(uint8_t *data, size_t len)
{
	wdns_msg_status status;
	status = wdns_deserialize_rrset(&rrset, data, len);
	if (status != wdns_msg_success)
		return (false);
	return (true);
}

void
freefunc(void)
{
	wdns_clear_rrset(&rrset);
}

bool
testfunc(void)
{
	wdns_print_rrset(stdout, &rrset, WDNS_MSG_SEC_ANSWER);
	return (true);
}
