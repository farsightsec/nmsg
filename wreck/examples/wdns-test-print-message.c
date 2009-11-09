#include <stdio.h>

#include "msg/msg.h"

void testfunc(wdns_message_t *m)
{
	wdns_print_message(stdout, m);
}
