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

/* Forward. */

static nmsg_output_t	output_open_stream(nmsg_stream_type, int, size_t);
static nmsg_res		output_write_callback(nmsg_output_t, nmsg_message_t);

/* Export. */

nmsg_output_t
nmsg_output_open_file(int fd, size_t bufsz) {
	return (output_open_stream(nmsg_stream_type_file, fd, bufsz));
}

nmsg_output_t
nmsg_output_open_sock(int fd, size_t bufsz) {
	return (output_open_stream(nmsg_stream_type_sock, fd, bufsz));
}

nmsg_output_t
nmsg_output_open_pres(int fd) {
	struct nmsg_output *output;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_pres;
	output->write_fp = _output_pres_write;

	output->pres = calloc(1, sizeof(*(output->pres)));
	if (output->pres == NULL) {
		free(output);
		return (NULL);
	}
	output->pres->fp = fdopen(fd, "w");
	if (output->pres->fp == NULL) {
		free(output->pres);
		free(output);
		return (NULL);
	}
	output->pres->endline = strdup("\n");
	pthread_mutex_init(&output->pres->lock, NULL);

	return (output);
}

nmsg_output_t
nmsg_output_open_callback(nmsg_cb_message cb, void *user) {
	struct nmsg_output *output;

	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_callback;
	output->write_fp = output_write_callback;

	output->callback = calloc(1, sizeof(*(output->callback)));
	if (output->callback == NULL) {
		free(output);
		return (NULL);
	}
	output->callback->cb = cb;
	output->callback->user = user;

	return (output);
}

nmsg_res
nmsg_output_flush(nmsg_output_t output) {
	return (output->flush_fp(output));
}

nmsg_res
nmsg_output_write(nmsg_output_t output, nmsg_message_t msg) {
	nmsg_res res;

	res = _nmsg_message_serialize(msg);
	if (res != nmsg_res_success)
		return (res);

	if (output->do_filter == true &&
	    (output->filter_vid != msg->np->vid ||
	     output->filter_msgtype != msg->np->msgtype))
	{
		return (nmsg_res_success);
	}

	res = output->write_fp(output, msg);
	return (res);
}

nmsg_res
nmsg_output_close(nmsg_output_t *output) {
	nmsg_res res;

	res = nmsg_res_success;
	switch ((*output)->type) {
	case nmsg_output_type_stream:
		if ((*output)->stream->estsz > NMSG_HDRLSZ_V2)
			res = _output_nmsg_flush(*output);
		if ((*output)->stream->random != NULL)
			nmsg_random_destroy(&((*output)->stream->random));
		if ((*output)->stream->rate != NULL)
			nmsg_rate_destroy(&((*output)->stream->rate));
		if ((*output)->stream->zb != NULL) {
			nmsg_zbuf_destroy(&((*output)->stream->zb));
			free((*output)->stream->zb_tmp);
		}
		if ((*output)->stream->nmsg != NULL)
			nmsg__nmsg__free_unpacked((*output)->stream->nmsg, NULL);
		_nmsg_buf_destroy(&(*output)->stream->buf);
		free((*output)->stream);
		break;
	case nmsg_output_type_pres:
		fclose((*output)->pres->fp);
		free((*output)->pres->endline);
		free((*output)->pres);
		break;
	case nmsg_output_type_callback:
		free((*output)->callback);
		break;
	}
	free(*output);
	*output = NULL;
	return (res);
}

void
nmsg_output_set_buffered(nmsg_output_t output, bool buffered) {
	if (output->type == nmsg_output_type_stream) {
		output->stream->buffered = buffered;
	} else if (output->type == nmsg_output_type_pres) {
		output->pres->flush = !(buffered);
	}
}

void
nmsg_output_set_filter_msgtype(nmsg_output_t output, unsigned vid, unsigned msgtype) {
	if (vid == 0 && msgtype == 0)
		output->do_filter = false;
	else
		output->do_filter = true;

	output->filter_vid = vid;
	output->filter_msgtype = msgtype;
}

nmsg_res
nmsg_output_set_filter_msgtype_byname(nmsg_output_t output,
				      const char *vname, const char *mname)
{
	unsigned vid, msgtype;

	if (vname == NULL || mname == NULL)
		return (nmsg_res_failure);

	vid = nmsg_msgmod_vname_to_vid(vname);
	if (vid == 0)
		return (nmsg_res_failure);
	msgtype = nmsg_msgmod_mname_to_msgtype(vid, mname);
	if (msgtype == 0)
		return (nmsg_res_failure);

	nmsg_output_set_filter_msgtype(output, vid, msgtype);

	return (nmsg_res_success);
}

void
nmsg_output_set_rate(nmsg_output_t output, nmsg_rate_t rate) {
	if (output->type != nmsg_output_type_stream)
		return;
	if (output->stream->rate != NULL)
		nmsg_rate_destroy(&output->stream->rate);
	output->stream->rate = rate;
}

void
nmsg_output_set_zlibout(nmsg_output_t output, bool zlibout) {
	if (output->type != nmsg_output_type_stream)
		return;

	if (zlibout == true) {
		if (output->stream->zb == NULL) {
			output->stream->zb = nmsg_zbuf_deflate_init();
			assert(output->stream->zb != NULL);
		}
		if (output->stream->zb_tmp == NULL) {
			output->stream->zb_tmp = calloc(1,
				output->stream->buf->bufsz);
			assert(output->stream->zb_tmp != NULL);
		}
	} else if (zlibout == false) {
		if (output->stream->zb != NULL)
			nmsg_zbuf_destroy(&output->stream->zb);
		if (output->stream->zb_tmp != NULL) {
			free(output->stream->zb_tmp);
			output->stream->zb_tmp = NULL;
		}
	}
}

void
nmsg_output_set_endline(nmsg_output_t output, const char *endline) {
	if (output->type == nmsg_output_type_pres) {
		if (output->pres->endline != NULL)
			free(output->pres->endline);
		output->pres->endline = strdup(endline);
	}
}

void
nmsg_output_set_source(nmsg_output_t output, unsigned source) {
	if (output->type == nmsg_output_type_stream)
		output->stream->source = source;
}

void
nmsg_output_set_operator(nmsg_output_t output, unsigned operator) {
	if (output->type == nmsg_output_type_stream)
		output->stream->operator = operator;
}

void
nmsg_output_set_group(nmsg_output_t output, unsigned group) {
	if (output->type == nmsg_output_type_stream)
		output->stream->group = group;
}

/* Private functions. */

static nmsg_output_t
output_open_stream(nmsg_stream_type type, int fd, size_t bufsz) {
	struct nmsg_output *output;

	/* nmsg_output */
	output = calloc(1, sizeof(*output));
	if (output == NULL)
		return (NULL);
	output->type = nmsg_output_type_stream;
	output->write_fp = _output_nmsg_write;
	output->flush_fp = _output_nmsg_flush;

	/* nmsg_stream_output */
	output->stream = calloc(1, sizeof(*(output->stream)));
	if (output->stream == NULL) {
		free(output);
		return (NULL);
	}
	output->stream->type = type;
	output->stream->buffered = true;
	output->stream->estsz = NMSG_HDRLSZ_V2;

	/* nmsg_buf */
	if (bufsz < NMSG_WBUFSZ_MIN)
		bufsz = NMSG_WBUFSZ_MIN;
	if (bufsz > NMSG_WBUFSZ_MAX)
		bufsz = NMSG_WBUFSZ_MAX;
	output->stream->buf = _nmsg_buf_new(bufsz);
	if (output->stream->buf == NULL) {
		free(output->stream);
		free(output);
		return (NULL);
	}
	output->stream->buf->fd = fd;
	output->stream->buf->bufsz = bufsz;
	pthread_mutex_init(&output->stream->lock, NULL);

	/* seed the rng, needed for fragment and sequence IDs */
	output->stream->random = nmsg_random_init();
	if (output->stream->random == NULL) {
		_nmsg_buf_destroy(&output->stream->buf);
		free(output->stream);
		free(output);
		return (NULL);
	}

	/* generate sequence ID */
	if (output->stream->type == nmsg_stream_type_sock) {
		nmsg_random_buf(output->stream->random,
				(uint8_t *) &output->stream->sequence_id,
				sizeof(output->stream->sequence_id));
	}

	return (output);
}

static nmsg_res
output_write_callback(nmsg_output_t output, nmsg_message_t msg) {
	output->callback->cb(msg, output->callback->user);
	return (nmsg_res_success);
}
