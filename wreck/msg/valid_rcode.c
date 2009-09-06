#include "private.h"

bool
wreck_valid_rcode(unsigned rcode)
{
	switch (rcode) {
	case WRECK_DNS_R_NOERROR:
	case WRECK_DNS_R_FORMERR:
	case WRECK_DNS_R_SERVFAIL:
	case WRECK_DNS_R_NXDOMAIN:
	case WRECK_DNS_R_NOTIMP:
	case WRECK_DNS_R_REFUSED:
	case WRECK_DNS_R_YXDOMAIN:
	case WRECK_DNS_R_YXRRSET:
	case WRECK_DNS_R_NXRRSET:
	case WRECK_DNS_R_NOTAUTH:
	case WRECK_DNS_R_NOTZONE:
	case WRECK_DNS_R_BADVERS:
	case WRECK_DNS_R_BADKEY:
	case WRECK_DNS_R_BADTIME:
	case WRECK_DNS_R_BADMODE:
	case WRECK_DNS_R_BADNAME:
	case WRECK_DNS_R_BADALG:
	case WRECK_DNS_R_BADTRUNC:
		return (true);
		break;
	default:
		return (false);
		break;
	}
}
