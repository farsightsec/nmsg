#include "private.h"

/**
 * Serialize a wdns_rrset_t.
 *
 * \param[in] rrset the RRset to serialize
 * \param[out] buf the output buffer (may be NULL)
 * \param[out] sz serialized length (may be NULL)
 *
 * \return wmsg_msg_success
 */

wdns_msg_status
wdns_serialize_rrset(const wdns_rrset_t *rrset, uint8_t *buf, size_t *sz)
{
	if (sz) {
		*sz = 1;			/* length of name */
		*sz += rrset->name.len;		/* name */
		*sz += 2;			/* type */
		*sz += 2;			/* class */
		*sz += 4;			/* ttl */
		*sz += 2;			/* number of rdatas */

		for (size_t i = 0; i < rrset->n_rdatas; i++) {
			/* rdata length */
			*sz += 2;

			/* rdata */
			*sz += rrset->rdatas[i]->len;
		}
	}

	if (buf) {
		/* length of name */
		*buf = (uint8_t) rrset->name.len;
		buf += 1;

		/* name */
		memcpy(buf, rrset->name.data, rrset->name.len);
		buf += rrset->name.len;

		/* type */
		memcpy(buf, &rrset->rrtype, 2);
		buf += 2;

		/* class */
		memcpy(buf, &rrset->rrclass, 2);
		buf += 2;

		/* ttl */
		memcpy(buf, &rrset->rrttl, 4);
		buf += 4;

		/* number of rdatas */
		memcpy(buf, &rrset->n_rdatas, 2);
		buf += 2;

		for (size_t i = 0; i < rrset->n_rdatas; i++) {
			uint16_t rdlen = rrset->rdatas[i]->len;

			/* rdata length */
			memcpy(buf, &rdlen, 2);
			buf += 2;

			/* rdata */
			memcpy(buf, &rrset->rdatas[i]->data, rdlen);
			buf += rdlen;
		}
	}

	return (wdns_msg_success);
}
