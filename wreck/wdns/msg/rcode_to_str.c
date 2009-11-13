#include "private.h"

const char *
wdns_rcode_to_str(uint16_t rcode)
{
	switch (rcode) {
	case WDNS_R_NOERROR:	return ("NOERROR");
	case WDNS_R_FORMERR:	return ("FORMERR");
	case WDNS_R_SERVFAIL:	return ("SERVFAIL");
	case WDNS_R_NXDOMAIN:	return ("NXDOMAIN");
	case WDNS_R_NOTIMP:	return ("NOTIMP");
	case WDNS_R_REFUSED:	return ("REFUSED");
	case WDNS_R_YXDOMAIN:	return ("YXDOMAIN");
	case WDNS_R_YXRRSET:	return ("YXRRSET");
	case WDNS_R_NXRRSET:	return ("NXRRSET");
	case WDNS_R_NOTAUTH:	return ("NOTAUTH");
	case WDNS_R_NOTZONE:	return ("NOTZONE");
	case WDNS_R_BADVERS:	return ("BADVERS");
	}

	return (NULL);
}
