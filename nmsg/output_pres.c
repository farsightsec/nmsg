/*
 * Copyright (c) 2008-2016 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Import. */

#include "private.h"

/* Internal functions. */

nmsg_res
_output_pres_write(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	char op_buf[sizeof("4294967295")] = {0}, group_buf[sizeof("4294967295")] = {0};
	const char *op_str = op_buf, *group_str = group_buf;
	const char *vname = NULL, *mname = NULL;
	char when[32];
	char *pres_data;
	uint32_t oper_val = 0, group_val = 0, source_val = 0;
	nmsg_msgmod_t mod;
	nmsg_res res;
	struct tm tm;
	time_t t;

	np = msg->np;

	/* lock output */
	pthread_mutex_lock(&output->pres->lock);

	t = np->time_sec;
	gmtime_r(&t, &tm);
	strftime(when, sizeof(when), "%Y-%m-%d %T", &tm);
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
	vname = nmsg_msgmod_vid_to_vname(np->vid);
	mname = nmsg_msgmod_msgtype_to_mname(np->vid, np->msgtype);

	if (output->pres->operator != 0)
		oper_val = output->pres->operator;
	else if (np->has_operator_)
		oper_val = np->operator_;

	if (oper_val != 0) {
		op_str = nmsg_alias_by_key(nmsg_alias_operator, oper_val);

		if (op_str == NULL) {
			snprintf(op_buf, sizeof(op_buf), "%"PRIu32, oper_val);
			op_str = op_buf;
		}
	}

	if (output->pres->group != 0)
		group_val = output->pres->group;
	else if (np->has_group)
		group_val = np->group;

	if (group_val != 0) {
		group_str = nmsg_alias_by_key(nmsg_alias_group, group_val);

		if (group_str == NULL) {
			snprintf(group_buf, sizeof(group_buf), "%"PRIu32, group_val);
			group_str = group_buf;
		}
	}

	if (output->pres->source != 0)
		source_val = output->pres->source;
	else if (np->has_source)
		source_val = np->source;

	fprintf(output->pres->fp, "[%zu] [%s.%09u] [%d:%d %s %s] "
		"[%08x] [%s] [%s] %s%s",
		np->has_payload ? np->payload.len : 0,
		when, np->time_nsec,
		np->vid, np->msgtype,
		vname ? vname : "(unknown)",
		mname ? mname : "(unknown)",
		source_val,
		op_str,
		group_str,
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
