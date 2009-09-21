#include "private.h"

/**
 * Compare an RR to a RRset. An RR and an RRset compare true if the name, type,
 * and class match.
 *
 * \param[in] rr the RR to compare
 * \param[in] rrset the RRset to compare
 *
 * \return true if the RR could be part of the RRset, false otherwise
 */

bool
wdns_compare_rr_rrset(const wdns_rr_t *rr, const wdns_rrset_t *rrset)
{
	if (rr->name.len == rrset->name.len &&
	    rr->rrtype == rrset->rrtype &&
	    rr->rrclass == rrset->rrclass)
	{
		return (strncasecmp(rr->name.data, rrset->name.data, rr->name.len) == 0);
	}

	return (false);
}
