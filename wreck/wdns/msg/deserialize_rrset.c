#include "private.h"

/**
 * Parse a serialized wdns_rrset_t.
 *
 * \param[out] rrset parsed RRset
 * \param[in] buf serialized RRset
 * \param[in] sz length of buf
 */

wdns_msg_status
wdns_deserialize_rrset(wdns_rrset_t *rrset, const uint8_t *buf, size_t sz)
{

#define copy_bytes(ptr, len) do { \
	if (bytes_read + len > sz) { \
		wdns_clear_rrset(rrset); \
		WDNS_ERROR(wdns_msg_err_overflow); \
	} \
	memcpy(ptr, buf, len); \
	buf += len; \
	bytes_read += len; \
} while(0)

	size_t bytes_read = 0;

	memset(rrset, 0, sizeof(*rrset));

	/* length of name */
	copy_bytes(&rrset->name.len, 1);

	/* name */
	rrset->name.data = malloc(rrset->name.len);
	if (rrset->name.data == NULL)
		WDNS_ERROR(wdns_msg_err_malloc);

	copy_bytes(rrset->name.data, rrset->name.len);

	/* type */
	copy_bytes(&rrset->rrtype, 2);

	/* class */
	copy_bytes(&rrset->rrclass, 2);

	/* ttl */
	copy_bytes(&rrset->rrttl, 4);

	/* number of rdatas */
	copy_bytes(&rrset->n_rdatas, 2);

	/* rdatas */
	rrset->rdatas = calloc(1, sizeof(void *) * rrset->n_rdatas);
	if (rrset->rdatas == NULL) {
		wdns_clear_rrset(rrset);
		WDNS_ERROR(wdns_msg_err_malloc);
	}
	for (size_t i = 0; i < rrset->n_rdatas; i++) {
		uint16_t rdlen;

		copy_bytes(&rdlen, 2);

		rrset->rdatas[i] = malloc(sizeof(rrset->rdatas[i]) + rdlen);
		if (rrset->rdatas[i] == NULL) {
			wdns_clear_rrset(rrset);
			WDNS_ERROR(wdns_msg_err_malloc);
		}
		
		rrset->rdatas[i]->len = rdlen;
		copy_bytes(&rrset->rdatas[i]->data, rdlen);
	}

	return (wdns_msg_success);
}
