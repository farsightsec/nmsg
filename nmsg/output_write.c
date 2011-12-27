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
output_flush_nmsg(nmsg_output_t output) {
	Nmsg__Nmsg *nmsg;
	nmsg_res res;

	/* lock output */
	pthread_mutex_lock(&output->stream->lock);

	res = nmsg_res_success;
	nmsg = output->stream->nmsg;

	/* if nmsg container isn't initialized, there is no work to do */
	if (nmsg == NULL)
		goto out;

	/* check if payload needs to be fragmented */
	if (output->stream->estsz > output->stream->buf->bufsz) {
		res = write_output_frag(output);
		free_payloads(nmsg);
		reset_estsz(output->stream);
		goto out;
	}

	/* flush output */
	res = write_pbuf(output);
	free_payloads(nmsg);
	reset_estsz(output->stream);

out:
	/* unlock output */
	pthread_mutex_unlock(&output->stream->lock);

	return (res);
}

static nmsg_res
output_write_nmsg(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__Nmsg *nmsg;
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	size_t np_len;

	/* detach payload from input */
	assert(msg->np != NULL);
	np = msg->np;
	msg->np = NULL;

	/* lock output */
	pthread_mutex_lock(&output->stream->lock);

	res = nmsg_res_success;
	nmsg = output->stream->nmsg;

	/* initialize nmsg container if necessary */
	if (nmsg == NULL) {
		nmsg = output->stream->nmsg = calloc(1, sizeof(Nmsg__Nmsg));
		if (nmsg == NULL) {
			res = nmsg_res_failure;
			goto error_out;
		}
		nmsg__nmsg__init(nmsg);
	}

	/* set source, output, group if necessary */
	if (output->stream->source != 0) {
		np->source = output->stream->source;
		np->has_source = 1;
	}
	if (output->stream->operator != 0) {
		np->operator_ = output->stream->operator;
		np->has_operator_ = 1;
	}
	if (output->stream->group != 0) {
		np->group = output->stream->group;
		np->has_group = 1;
	}

	/* calculate size of serialized payload */
	np_len = _nmsg_payload_size(np);

	/* check for overflow */
	if (output->stream->estsz != NMSG_HDRLSZ_V2 &&
	    output->stream->estsz + np_len + 24 >= output->stream->buf->bufsz)
	{
		/* finalize and write out the container */
		res = write_pbuf(output);
		if (res != nmsg_res_success) {
			free_payloads(nmsg);
			reset_estsz(output->stream);
			goto error_out;
		}
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

	/* crc field */
	output->stream->estsz += 6;

	/* sequence field */
	if (nmsg->has_sequence)
		output->stream->estsz += 6;

	/* sequence_id field */
	if (nmsg->has_sequence_id)
		output->stream->estsz += 12;

	/* increment estimated size of serialized container */
	output->stream->estsz += np_len;

	/* append payload to container */
	nmsg->payloads = realloc(nmsg->payloads,
				 ++(nmsg->n_payloads) * sizeof(void *));
	if (nmsg->payloads == NULL) {
		res = nmsg_res_memfail;
		goto error_out;
	}
	nmsg->payloads[nmsg->n_payloads - 1] = np;

	/* check if payload needs to be fragmented */
	if (output->stream->estsz > output->stream->buf->bufsz) {
		res = write_output_frag(output);
		free_payloads(nmsg);
		reset_estsz(output->stream);
		goto out;
	}

	/* flush output if unbuffered */
	if (output->stream->buffered == false) {
		res = write_pbuf(output);
		free_payloads(nmsg);
		reset_estsz(output->stream);

		/* sleep a bit if necessary */
		if (output->stream->rate != NULL)
			nmsg_rate_sleep(output->stream->rate);
	}

out:
	/* unlock output */
	pthread_mutex_unlock(&output->stream->lock);

	return (res);

error_out:
	/* unlock output */
	pthread_mutex_unlock(&output->stream->lock);

	/* give the payload back to the caller */
	msg->np = np;

	return (res);
}

static nmsg_res
output_write_pres(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	char *pres_data;
	char when[32];
	nmsg_msgmod_t mod;
	nmsg_res res;
	struct tm *tm;
	time_t t;

	np = msg->np;

	/* lock output */
	pthread_mutex_lock(&output->pres->lock);

	t = np->time_sec;
	tm = gmtime(&t);
	strftime(when, sizeof(when), "%Y-%m-%d %T", tm);
	mod = nmsg_msgmod_lookup(np->vid, np->msgtype);
	if (mod != NULL) {
		res = nmsg_message_to_pres(msg, &pres_data, output->pres->endline);
		if (res != nmsg_res_success)
			goto out;
	} else {
		nmsg_asprintf(&pres_data, "<UNKNOWN NMSG %u:%u>%s",
			      np->vid, np->msgtype,
			      output->pres->endline);
	}
	fprintf(output->pres->fp, "[%zu] [%s.%09u] [%d:%d %s %s] "
		"[%08x] [%s] [%s] %s%s",
		np->has_payload ? np->payload.len : 0,
		when, np->time_nsec,
		np->vid, np->msgtype,
		nmsg_msgmod_vid_to_vname(np->vid),
		nmsg_msgmod_msgtype_to_mname(np->vid, np->msgtype),
		np->has_source ? np->source : 0,

		np->has_operator_ ?
			nmsg_alias_by_key(nmsg_alias_operator, np->operator_)
			: "",

		np->has_group ?
			nmsg_alias_by_key(nmsg_alias_group, np->group)
			: "",

		output->pres->endline, pres_data);
	fputs("\n", output->pres->fp);
	if (output->pres->flush)
		fflush(output->pres->fp);

	free(pres_data);
out:
	/* unlock output */
	pthread_mutex_unlock(&output->pres->lock);

	return (nmsg_res_success);
}

static nmsg_res
output_write_callback(nmsg_output_t output, nmsg_message_t msg) {
	output->callback->cb(msg, output->callback->user);

	return (nmsg_res_success);
}
