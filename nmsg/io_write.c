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
io_write_payload_nmsg(struct nmsg_io_thr *iothr,
		      struct nmsg_io_output *io_output,
		      Nmsg__NmsgPayload **np)
{
	nmsg_io_t io;
	nmsg_res res;
	struct nmsg_io_close_event ce;

	io = iothr->io;

	if (io->n_user > 0) {
		size_t user_bytes = io->n_user * sizeof(*((*np)->user));
		(*np)->user = malloc(user_bytes);
		if ((*np)->user == NULL)
			return (nmsg_res_memfail);
		memcpy((*np)->user, io->user, user_bytes);
		(*np)->n_user = io->n_user;
	}

	res = nmsg_output_append(io_output->output, *np);
	if (!(res == nmsg_res_success ||
	      res == nmsg_res_pbuf_written))
		return (nmsg_res_failure);

	io_output->count_nmsg_payload_out += 1;

	pthread_mutex_lock(&io->lock);
	io->count_nmsg_payload_out += 1;
	pthread_mutex_unlock(&io->lock);

	res = nmsg_res_success;

	if (io->count > 0 &&
	    io_output->count_nmsg_payload_out % io->count == 0)
	{
		if (io_output->user != NULL) {
			ce.io = io;
			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_count;
			ce.output_type = io_output->output->type;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			nmsg_output_set_zlibout(io_output->output, io->zlibout);
		} else {
			io->stop = true;
			res = nmsg_res_stop;
		}
	}

	if (io->interval > 0 &&
	    (iothr->now.tv_sec - io_output->last.tv_sec) >=
		    (time_t) io->interval)
	{
		if (io_output->user != NULL) {
			struct timespec now = iothr->now;
			now.tv_nsec = 0;
			now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);
			io_output->last = now;

			ce.io_type = nmsg_io_io_type_output;
			ce.close_type = nmsg_io_close_type_interval;
			ce.io = io;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			nmsg_output_set_zlibout(io_output->output, io->zlibout);
		} else {
			io->stop = true;
			res = nmsg_res_stop;
		}
	}
	return (res);
}

static nmsg_res
io_write_payload_pres(struct nmsg_io_thr *iothr,
		      struct nmsg_io_output *io_output,
		      Nmsg__NmsgPayload **np)
{
	char *pres_data;
	char when[32];
	nmsg_pbmod_t mod;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_close_event ce;
	struct nmsg_pres *pres;
	struct tm *tm;
	time_t t;

	pres = io_output->output->pres;
	io = iothr->io;
	t = (*np)->time_sec;
	tm = gmtime(&t);
	strftime(when, sizeof(when), "%Y-%m-%d %T", tm);
	mod = nmsg_pbmodset_lookup(io->ms, (*np)->vid, (*np)->msgtype);
	if (mod != NULL) {
		res = nmsg_pbmod_pbuf_to_pres(mod, *np, &pres_data,
					      io->endline);
		if (res != nmsg_res_success)
			return (res);
	} else {
		nmsg_asprintf(&pres_data, "<UNKNOWN NMSG %u:%u>%s",
			      (*np)->vid, (*np)->msgtype,
			      io->endline);
	}
	if (io->quiet == false)
		fprintf(pres->fp, "[%zu] %s.%09u [%d:%d %s %s] "
			"[%08x %08x] %s%s",
			(*np)->has_payload ? (*np)->payload.len : 0,
			when, (*np)->time_nsec,
			(*np)->vid, (*np)->msgtype,
			nmsg_pbmodset_vid_to_vname(io->ms, (*np)->vid),
			nmsg_pbmodset_msgtype_to_mname(io->ms, (*np)->vid,
						       (*np)->msgtype),
			(*np)->n_user >= 1 ? (*np)->user[0] : 0,
			(*np)->n_user >= 2 ? (*np)->user[1] : 0,
			io->endline, pres_data);
	else
		fputs(pres_data, pres->fp);
	fputs(io->endline, pres->fp);
	free(pres_data);

	io_output->count_nmsg_payload_out += 1;

	res = nmsg_res_success;

	if (io->count > 0 &&
	    io_output->count_nmsg_payload_out % io->count == 0)
	{
		if (io_output->user != NULL) {
			ce.io_type = nmsg_io_io_type_output;
			ce.output_type = io_output->output->type;
			ce.close_type = nmsg_io_close_type_count;
			ce.io = io;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			if (io_output->output == NULL) {
				res = nmsg_res_failure;
				goto out;
			}
		} else {
			io->stop = true;
			res = nmsg_res_stop;
			goto out;
		}
	}

	if (io->interval > 0 &&
	    iothr->now.tv_sec - io_output->last.tv_sec >= (time_t) io->interval)
	{
		if (io_output->user != NULL) {
			struct timespec now = iothr->now;
			now.tv_nsec = 0;
			now.tv_sec = now.tv_sec - (now.tv_sec % io->interval);
			io_output->last = now;

			ce.io_type = nmsg_io_io_type_output;
			ce.output_type = io_output->output->type;
			ce.close_type = nmsg_io_close_type_interval;
			ce.io = io;
			ce.user = io_output->user;
			nmsg_output_close(&io_output->output);
			ce.output = &io_output->output;
			io->closed_fp(&ce);
			if (io_output->output->pres->fp == NULL) {
				res = nmsg_res_failure;
				goto out;
			}
		} else {
			io->stop = true;
			res = nmsg_res_stop;
			goto out;
		}
	}

out:
	nmsg_payload_free(np);
	return (res);
}

static nmsg_res
io_write_mirrored(struct nmsg_io_thr *iothr, Nmsg__NmsgPayload *np) {
	Nmsg__NmsgPayload *npdup;
	nmsg_res res;
	struct nmsg_io *io;
	struct nmsg_io_output *io_output;

	io = iothr->io;

	for (io_output = ISC_LIST_HEAD(io->io_outputs);
	     io_output != NULL;
	     io_output = ISC_LIST_NEXT(io_output, link));
	{
		npdup = nmsg_payload_dup(np);

		pthread_mutex_lock(&io_output->lock);
		res = io_output->write_fp(iothr, io_output, &npdup);
		pthread_mutex_unlock(&io_output->lock);

		if (res != nmsg_res_success) {
			nmsg_payload_free(&npdup);
			nmsg_payload_free(&np);
			return (res);
		}
	}
	nmsg_payload_free(&np);

	return (nmsg_res_success);
}
