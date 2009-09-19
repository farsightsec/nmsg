#include "private.h"

const char *
wdns_class_to_str(uint16_t dns_class)
{
	switch (dns_class) {
	case WDNS_CLASS_IN:	return ("IN");
	case WDNS_CLASS_CH:	return ("CH");
	case WDNS_CLASS_HS:	return ("HS");
	case WDNS_CLASS_NONE:	return ("NONE");
	case WDNS_CLASS_ANY:	return ("ANY");
	}

	return (NULL);
}
