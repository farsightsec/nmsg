/*
 * Copyright (c) 2008, 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Private. */

static nmsg_res
output_write_nmsg(nmsg_output_t output, Nmsg__NmsgPayload *np) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;
	size_t np_len;

	res = nmsg_res_success;
	nmsg = output->stream->nmsg;

	/* add user fields */
	if (output->stream->n_user > 0) {
		size_t user_bytes = output->stream->n_user *
			sizeof(*(np->user));
		np->user = malloc(user_bytes);
		if (np->user == NULL)
			return (nmsg_res_memfail);
		memcpy(np->user, output->stream->user, user_bytes);
		np->n_user = output->stream->n_user;
	}

	/* initialize nmsg container if necessary */
	if (nmsg == NULL) {
		nmsg = output->stream->nmsg = calloc(1, sizeof(Nmsg__Nmsg));
		if (nmsg == NULL)
			return (nmsg_res_failure);
		nmsg__nmsg__init(nmsg);
	}

	/* calculate size of serialized payload */
	np_len = nmsg_payload_size(np);

	/* check for overflow */
	if (output->stream->estsz != NMSG_HDRLSZ_V2 &&
	    output->stream->estsz + np_len + 16 >= output->stream->buf->bufsz)
	{
		/* finalize and write out the container */
		res = write_pbuf(output);
		if (res != nmsg_res_success) {
			if (np->has_payload && np->payload.data != NULL)
				free(np->payload.data);
			free(np);
			free_payloads(nmsg);
			reset_estsz(output->stream);
			return (res);
		}
		res = nmsg_res_nmsg_written;
		free_payloads(nmsg);
		reset_estsz(output->stream);
	}

	/* sleep a bit if necessary */
	if (output->stream->rate != NULL)
		nmsg_rate_sleep(output->stream->rate);

	/* field tag */
	output->stream->estsz += 1;

	/* varint encoded length */
	output->stream->estsz += 1;
	if (np_len >= (1 << 7))
		output->stream->estsz += 1;
	if (np_len >= (1 << 14))
		output->stream->estsz += 1;
	if (np_len >= (1 << 21))
		output->stream->estsz += 1;

	/* increment estimated size of serialized container */
	output->stream->estsz += np_len;

	/* append payload to container */
	nmsg->payloads = realloc(nmsg->payloads,
				 ++(nmsg->n_payloads) * sizeof(void *));
	if (nmsg->payloads == NULL)
		return (nmsg_res_memfail);
	nmsg->payloads[nmsg->n_payloads - 1] = np;

	/* check if payload needs to be fragmented */
	if (output->stream->estsz > output->stream->buf->bufsz) {
		res = write_output_frag(output);
		free_payloads(nmsg);
		reset_estsz(output->stream);
		return (res);
	}

	/* flush output if unbuffered */
	if (output->stream->buffered == false) {
		res = write_pbuf(output);
		if (res == nmsg_res_success)
			res = nmsg_res_nmsg_written;
		free_payloads(nmsg);
		reset_estsz(output->stream);

		/* sleep a bit if necessary */
		if (output->stream->rate != NULL)
			nmsg_rate_sleep(output->stream->rate);
	}

	return (res);
}

static nmsg_res
output_write_pres(nmsg_output_t output, Nmsg__NmsgPayload *np) {
	char *pres_data;
	char when[32];
	nmsg_pbmod_t mod;
	nmsg_res res;
	struct tm *tm;
	time_t t;

	t = np->time_sec;
	tm = gmtime(&t);
	strftime(when, sizeof(when), "%Y-%m-%d %T", tm);
	mod = nmsg_pbmodset_lookup(output->pres->ms, np->vid, np->msgtype);
	if (mod != NULL) {
		res = nmsg_pbmod_pbuf_to_pres(mod, np, &pres_data,
					      output->pres->endline);
		if (res != nmsg_res_success)
			return (res);
	} else {
		nmsg_asprintf(&pres_data, "<UNKNOWN NMSG %u:%u>%s",
			      np->vid, np->msgtype,
			      output->pres->endline);
	}
	fprintf(output->pres->fp, "[%zu] %s.%09u [%d:%d %s %s] "
		"[%08x %08x]%s%s",
		np->has_payload ? np->payload.len : 0,
		when, np->time_nsec,
		np->vid, np->msgtype,
		nmsg_pbmodset_vid_to_vname(output->pres->ms, np->vid),
		nmsg_pbmodset_msgtype_to_mname(output->pres->ms, np->vid,
					       np->msgtype),
		np->n_user >= 1 ? np->user[0] : 0,
		np->n_user >= 2 ? np->user[1] : 0,
		output->pres->endline, pres_data);
	fputs("\n", output->pres->fp);

	free(pres_data);
	nmsg_payload_free(&np);

	return (nmsg_res_success);
}
