#include "private.h"

static wdns_msg_status
gen_label_offsets(wdns_name_t *name, size_t n_labels, uint8_t *offsets)
{
	size_t n = 0;
	uint8_t c, *data;

	data = name->data;

	while ((c = *data) != 0) {
		if (c <= 63) {
			offsets[n++] = data - name->data;
			if (n == n_labels)
				return (wdns_msg_success);
			data += c;
			if (data - name->data > name->len)
				WDNS_ERROR(wdns_msg_err_name_overflow);
		} else {
			WDNS_ERROR(wdns_msg_err_invalid_length_octet);
		}
		data++;
	}
	return (wdns_msg_success);
}

static bool
compare_label(uint8_t *l0, uint8_t *l1)
{
	uint8_t len0, len1;
	len0 = *l0++;
	len1 = *l1++;
	if (len0 == len1)
		return (memcmp(l0, l1, len0) == 0);
	return (false);
}

/**
 * Determine if a name is a subdomain of another domain.
 *
 * A domain is not a subdomain of itself.
 *
 * \param[in] n0
 * \param[in] n1
 * \param[out] is_subdomain
 *
 * \return wdns_msg_success
 * \return wdns_msg_err_parse_error
 */

wdns_msg_status
wdns_is_subdomain(wdns_name_t *n0, wdns_name_t *n1, bool *is_subdomain)
{
	wdns_msg_status status;
	size_t n0_nlabels, n1_nlabels;
	ssize_t n0_idx, n1_idx;
	uint8_t *n0_offsets, *n1_offsets;

	*is_subdomain = false;

	/* count the number of labels in each name */	
	status = wdns_count_labels(n0, &n0_nlabels);
	if (status != wdns_msg_success)
		WDNS_ERROR(wdns_msg_err_parse_error);

	status = wdns_count_labels(n1, &n1_nlabels);
	if (status != wdns_msg_success)
		WDNS_ERROR(wdns_msg_err_parse_error);

	/* exclude any cases that can be determined solely by label counts */
	if (n0_nlabels <= n1_nlabels) {
		/* a subdomain must have more labels than any of its parents */
		return (wdns_msg_success);
	}
	if (n0_nlabels == 0) {
		/* the root cannot be a subdomain of any other domain */
		return (wdns_msg_success);
	}
	if (n1_nlabels == 0) {
		/* all other domains are subdomains of the root */
		*is_subdomain = true;
		return (wdns_msg_success);
	}

	/* for each name, create an array of label offsets */
	n0_offsets = alloca(n0_nlabels);
	n1_offsets = alloca(n1_nlabels);

	status = gen_label_offsets(n0, n0_nlabels, n0_offsets);
	if (status != wdns_msg_success)
		WDNS_ERROR(wdns_msg_err_parse_error);

	status = gen_label_offsets(n1, n1_nlabels, n1_offsets);
	if (status != wdns_msg_success)
		WDNS_ERROR(wdns_msg_err_parse_error);

	/* compare each label, right-to-left */
	n0_idx = n0_nlabels - 1;
	n1_idx = n1_nlabels - 1;
	do {
		if (!compare_label(n0->data + n0_offsets[n0_idx],
				   n1->data + n1_offsets[n1_idx]))
		{
			return (wdns_msg_success);
		}
		n0_idx--;
		n1_idx--;
	} while (n1_idx >= 0);

	/* all labels of the potential parent domain have compared true,
	 * thus n1 is a suffix of n0 */
	*is_subdomain = true;
	return (wdns_msg_success);
}
