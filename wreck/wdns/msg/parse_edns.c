#include "private.h"

wdns_msg_status
_wdns_parse_edns(wdns_message_t *m, wdns_rr_t *rr)
{
	m->edns.present = true;
	m->edns.size = rr->rrclass;
	m->edns.version = (rr->rrttl >> 16) & 0xFF;
	m->edns.flags = rr->rrttl & 0xFFFF;
	m->edns.options = rr->rdata;
	rr->rdata = NULL;

	m->rcode |= (rr->rrttl >> 16) & 0xFF00;

	wdns_clear_rr(rr);

	return (wdns_msg_success);
}
