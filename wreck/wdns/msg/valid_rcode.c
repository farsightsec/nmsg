#include "private.h"

bool
wdns_valid_rcode(unsigned rcode)
{
	switch (rcode) {
	case WDNS_R_NOERROR:
	case WDNS_R_FORMERR:
	case WDNS_R_SERVFAIL:
	case WDNS_R_NXDOMAIN:
	case WDNS_R_NOTIMP:
	case WDNS_R_REFUSED:
	case WDNS_R_YXDOMAIN:
	case WDNS_R_YXRRSET:
	case WDNS_R_NXRRSET:
	case WDNS_R_NOTAUTH:
	case WDNS_R_NOTZONE:
	case WDNS_R_BADVERS:
	case WDNS_R_BADKEY:
	case WDNS_R_BADTIME:
	case WDNS_R_BADMODE:
	case WDNS_R_BADNAME:
	case WDNS_R_BADALG:
	case WDNS_R_BADTRUNC:
		return (true);
		break;
	default:
		return (false);
		break;
	}
}
