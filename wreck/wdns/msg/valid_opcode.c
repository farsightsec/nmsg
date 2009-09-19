#include "private.h"

bool
wdns_valid_opcode(unsigned opcode)
{
	switch (opcode) {
	case WDNS_OP_QUERY:
	case WDNS_OP_IQUERY:
	case WDNS_OP_STATUS:
	case WDNS_OP_NOTIFY:
	case WDNS_OP_UPDATE:
		return (true);
		break;
	default:
		return (false);
		break;
	}
}
