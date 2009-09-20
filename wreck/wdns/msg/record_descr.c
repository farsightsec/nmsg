#include "private.h"
#include "record_descr.h"

const record_descr record_descr_array[] = {
	/* RFC 1035 class insensitive well-known types */

	[WDNS_TYPE_CNAME] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_HINFO] =
		{ class_un, { rdf_string, rdf_string, rdf_end } },

	[WDNS_TYPE_MB] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MD] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MF] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MG] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MINFO] =
		{ class_un, { rdf_name, rdf_name, rdf_end } },

	[WDNS_TYPE_MR] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_MX] =
		{ class_un, { rdf_int16, rdf_name, rdf_end } },

	[WDNS_TYPE_NS] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_NULL] =
		{ class_un, { rdf_bytes, rdf_end } },

	[WDNS_TYPE_PTR] =
		{ class_un, { rdf_name, rdf_end } },

	[WDNS_TYPE_SOA] =
		{ class_un, { rdf_name, rdf_name, rdf_int32, rdf_int32, rdf_int32,
				rdf_int32, rdf_int32, rdf_end } },

	[WDNS_TYPE_TXT] =
		{ class_un, { rdf_repstring, rdf_end } },

	/* RFC 1035 Internet class well-known types */

	[WDNS_TYPE_A] =
		{ class_in, { rdf_int32, rdf_end } },

	[WDNS_TYPE_WKS] =
		{ class_in, { rdf_int32, rdf_int8, rdf_bytes, rdf_end } },

	/* post-RFC 1035 class insensitive types */

	[WDNS_TYPE_AFSDB] =
		{ class_un, { rdf_int16, rdf_name, rdf_end } },

	[WDNS_TYPE_ISDN] =
		{ class_un, { rdf_string, rdf_string, rdf_end } },

	[WDNS_TYPE_RP] =
		{ class_un, { rdf_name, rdf_name, rdf_end } },

	[WDNS_TYPE_RT] =
		{ class_un, { rdf_int16, rdf_name, rdf_end } },

	[WDNS_TYPE_X25] =
		{ class_un, { rdf_string, rdf_end } },

	[WDNS_TYPE_NXT] =
		{ class_un, { rdf_name, rdf_bytes, rdf_end } },

	[WDNS_TYPE_SIG] =
		{ class_un, { rdf_int16, rdf_int8, rdf_int8, rdf_int32, rdf_int32, rdf_int32,
				rdf_int16, rdf_name, rdf_bytes, rdf_end } },

	[WDNS_TYPE_DNAME] =
		{ class_un, { rdf_uname, rdf_end } },

	/* post-RFC 1035 Internet class types */

	[WDNS_TYPE_A6] =
		{ class_in, { rdf_ipv6prefix, rdf_uname, rdf_end } },

	[WDNS_TYPE_AAAA] =
		{ class_in, { rdf_int128, rdf_end } },

	[WDNS_TYPE_KX] =
		{ class_in, { rdf_int16, rdf_uname, rdf_end } },

	[WDNS_TYPE_PX] =
		{ class_in, { rdf_int16, rdf_name, rdf_name, rdf_end } },

	[WDNS_TYPE_NAPTR] =
		{ class_in, { rdf_int16, rdf_int16, rdf_string, rdf_string, rdf_string,
				rdf_name, rdf_end } },

	[WDNS_TYPE_SRV] =
		{ class_in, { rdf_int16, rdf_int16, rdf_int16, rdf_name, rdf_end } },
};

const size_t record_descr_len = sizeof(record_descr_array) / sizeof(record_descr);
