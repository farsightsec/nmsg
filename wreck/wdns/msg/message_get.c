#include "private.h"

uint16_t
wdns_message_get_id(wdns_message_t *m) {
	return (m->id);
}

uint16_t
wdns_message_get_flags(wdns_message_t *m) {
	return (m->flags);
}

uint16_t
wdns_message_get_rcode(wdns_message_t *m) {
	return (m->rcode);
}
