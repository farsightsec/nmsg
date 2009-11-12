#include "private.h"

const char *
wdns_opcode_to_str(uint16_t opcode)
{
	switch (opcode) {
	case WDNS_OP_QUERY:	return ("QUERY");
	case WDNS_OP_IQUERY:	return ("IQUERY");
	case WDNS_OP_STATUS:	return ("STATUS");
	case WDNS_OP_NOTIFY:	return ("NOTIFY");
	case WDNS_OP_UPDATE:	return ("UPDATE");
	}

	return (NULL);
}
