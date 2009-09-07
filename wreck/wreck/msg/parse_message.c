#include "private.h"

static bool
compare_rr_rrset(wreck_dns_rr_t *rr, wreck_dns_rrset_t *rrset)
{
	if (rr->name.len == rrset->name.len &&
	    rr->rrtype == rrset->rrtype &&
	    rr->rrclass == rrset->rrclass)
	{
		return (memcmp(rr->name.data, rrset->name.data, rr->name.len) == 0);
	}

	return (false);
}

static wreck_msg_status
insert_rr(wreck_dns_rrset_array_t *a, wreck_dns_rr_t *rr)
{
	bool found_rrset = false;
	wreck_dns_rdata_t *rdata;
	wreck_dns_rrset_t *rrset;

	/* iterate over RRset array backwards */
	for (unsigned i = a->n_rrsets; i > 0; i--) {
		rrset = a->rrsets[i - 1];

		if (compare_rr_rrset(rr, rrset)) {
			/* this RR is part of the RRset */
			rrset->n_rdatas += 1;
			rrset->rdatas = realloc(rrset->rdatas,
						rrset->n_rdatas * sizeof(*(rrset->rdatas)));
			if (rrset->rdatas == NULL)
				WRECK_ERROR(wreck_msg_err_malloc);

			/* detach the rdata from the RR and give it to the RRset */
			rdata = rr->rdata;
			rr->rdata = NULL;
			rrset->rdatas[rrset->n_rdatas - 1] = rdata;

			/* use the lowest TTL out of the RRs for the RRset itself */
			if (rr->rrttl < rrset->rrttl)
				rrset->rrttl = rr->rrttl;

			found_rrset = true;
			break;
		}
	}

	if (found_rrset == false) {
		/* create a new RRset */
		rrset = malloc(sizeof(*rrset));
		if (rrset == NULL)
			WRECK_ERROR(wreck_msg_err_malloc);

		/* copy fields from the RR */
		rrset->rrttl = rr->rrttl;
		rrset->rrtype = rr->rrtype;
		rrset->rrclass = rr->rrclass;

		/* add rdata */
		rrset->n_rdatas = 1;
		rrset->rdatas = malloc(sizeof(*(rrset->rdatas)));
		if (rrset->rdatas == NULL) {
			free(rrset);
			WRECK_ERROR(wreck_msg_err_malloc);
		}

		/* detach the owner name from the RR and give it to the RRset */
		rrset->name.len = rr->name.len;
		rrset->name.data = rr->name.data;
		rr->name.len = 0;
		rr->name.data = NULL;

		/* detach the rdata from the RR and give it to the RRset */
		rdata = rr->rdata;
		rr->rdata = NULL;
		rrset->rdatas[0] = rdata;

		/* attach the RRset to the RRset array */
		a->n_rrsets += 1;
		a->rrsets = realloc(a->rrsets, a->n_rrsets * sizeof(*(a->rrsets)));
		if (a->rrsets == NULL) {
			wreck_dns_rrset_clear(rrset);
			free(rrset);
			WRECK_ERROR(wreck_msg_err_malloc);
		}
		a->rrsets[a->n_rrsets - 1] = rrset;
	}

	return (wreck_msg_success);
}

wreck_msg_status
wreck_parse_message(const uint8_t *op, const uint8_t *eop, wreck_dns_message_t *m)
{
	const uint8_t *p = op;
	size_t n, rrlen;
	uint16_t qdcount, ancount, nscount, arcount;
	uint32_t len = eop - op;
	wreck_dns_rr_t rr;
	wreck_msg_status status;

	memset(m, 0, sizeof(*m));

	if (len < WRECK_DNS_LEN_HEADER) {
		VERBOSE("op=%p eop=%p\n", op, eop);
		WRECK_ERROR(wreck_msg_err_len);
	}

	WRECK_BUF_GET16(m->id, p);
	WRECK_BUF_GET16(m->flags, p);
	WRECK_BUF_GET16(qdcount, p);
	WRECK_BUF_GET16(ancount, p);
	WRECK_BUF_GET16(nscount, p);
	WRECK_BUF_GET16(arcount, p);

	len -= WRECK_DNS_LEN_HEADER;

	VERBOSE("Parsing DNS message id=%#.2x flags=%#.2x "
		"qd=%u an=%u ns=%u ar=%u\n",
		m->id, m->flags, qdcount, ancount, nscount, arcount);

	if (qdcount == 1) {
		status = wreck_parse_question_record(p, eop, &m->question);
		if (status != wreck_msg_success)
			WRECK_ERROR(wreck_msg_err_parse_error);
#if DEBUG
		VERBOSE("QUESTION RR\n");
		wreck_print_question_record(stdout, &m->question);
#endif
		/* skip qname */
		WRECK_BUF_ADVANCE(p, len, m->question.name.len);

		/* skip qtype and qclass */
		WRECK_BUF_ADVANCE(p, len, 4);

		if (ancount == 0 && nscount == 0 && arcount == 0) {
			/* if there are no more records to parse then this must be
			 * the end of the packet */
			if (p == eop) {
				return (wreck_msg_success);
			} else {
				VERBOSE("WARNING: trailing garbage p=%p eop=%p\n", p, eop);
			}
		}
	} else if (qdcount > 1) {
		WRECK_ERROR(wreck_msg_err_parse_error);
	}

	for (n = 0; n < ancount; n++) {
		VERBOSE("ANSWER RR %zd\n", n);
		status = wreck_parse_message_rr(op, eop, p, &rrlen, &rr);
		if (status != wreck_msg_success) {
			wreck_dns_message_clear(m);
			WRECK_ERROR(wreck_msg_err_parse_error);
		}
		status = insert_rr(&m->answer, &rr);
		if (status != wreck_msg_success)
			goto err;
		wreck_dns_rr_clear(&rr);
		p += rrlen;
	}

	for (n = 0; n < nscount; n++) {
		VERBOSE("AUTHORITY RR %zd\n", n);
		status = wreck_parse_message_rr(op, eop, p, &rrlen, &rr);
		if (status != wreck_msg_success) {
			wreck_dns_message_clear(m);
			WRECK_ERROR(wreck_msg_err_parse_error);
		}
		status = insert_rr(&m->authority, &rr);
		if (status != wreck_msg_success)
			goto err;
		wreck_dns_rr_clear(&rr);
		p += rrlen;
	}

	for (n = 0; n < arcount; n++) {
		VERBOSE("ADDITIONAL RR %zd\n", n);
		status = wreck_parse_message_rr(op, eop, p, &rrlen, &rr);
		if (status != wreck_msg_success) {
			wreck_dns_message_clear(m);
			WRECK_ERROR(wreck_msg_err_parse_error);
		}
		status = insert_rr(&m->additional, &rr);
		if (status != wreck_msg_success)
			goto err;
		wreck_dns_rr_clear(&rr);
		p += rrlen;
	}

	return (wreck_msg_success);
err:
	wreck_dns_rr_clear(&rr);
	wreck_dns_message_clear(m);
	WRECK_ERROR(status);
}
