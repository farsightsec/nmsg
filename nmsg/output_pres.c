/*
 * Copyright (c) 2008-2012 by Internet Systems Consortium, Inc. ("ISC")
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

/* Import. */

#include "private.h"

/* Internal functions. */

nmsg_res
_output_pres_write(nmsg_output_t output, nmsg_message_t msg) {
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
