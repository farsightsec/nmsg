#include "private.h"

bool
wreck_valid_opcode(unsigned opcode)
{
	switch (opcode) {
	case WRECK_DNS_OP_QUERY:
	case WRECK_DNS_OP_IQUERY:
	case WRECK_DNS_OP_STATUS:
	case WRECK_DNS_OP_NOTIFY:
	case WRECK_DNS_OP_UPDATE:
		return (true);
		break;
	default:
		return (false);
		break;
	}
}
