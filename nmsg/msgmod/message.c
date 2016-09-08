/*
 * Copyright (c) 2009-2012, 2015 by Farsight Security, Inc.
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

#include "transparent.h"

/* Export. */

struct nmsg_message *
nmsg_message_init(struct nmsg_msgmod *mod) {
	struct nmsg_message *msg;
	nmsg_res res;

	/* allocate space */
	msg = calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	/* initialize ->mod */
	msg->mod = mod;

	/* initialize ->message */
	res = _nmsg_message_init_message(msg);
	if (res != nmsg_res_success) {
		free(msg);
		return (NULL);
	}

	/* initialize ->np */
	res = _nmsg_message_init_payload(msg);
	if (res != nmsg_res_success) {
		free(msg->message);
		free(msg);
		return (NULL);
	}

	return (msg);
}

nmsg_res
_nmsg_message_dup_protobuf(const struct nmsg_message *msg, ProtobufCMessage **dst) {
	ProtobufCBufferSimple sbuf = {0};

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.data = malloc(1024);
	if (sbuf.data == NULL)
		return (nmsg_res_memfail);
	sbuf.must_free_data = 1;
	sbuf.alloced = 1024;

	protobuf_c_message_pack_to_buffer(msg->message, (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL)
		return (nmsg_res_memfail);

	*dst = protobuf_c_message_unpack(msg->mod->plugin->pbdescr, NULL,
					 sbuf.len, sbuf.data);
	free(sbuf.data);
	if (*dst == NULL)
		return (nmsg_res_memfail);

	return (nmsg_res_success);
}

struct nmsg_message *
_nmsg_message_dup(struct nmsg_message *msg) {
	nmsg_res res;
	struct nmsg_message *msgdup;

	/* allocate space */
	msgdup = calloc(1, sizeof(*msgdup));
	if (msgdup == NULL)
		return (NULL);

	/* initialize ->mod */
	msgdup->mod = msg->mod;

	/* initialize ->message */
	if (msg->message != NULL &&
	    msg->mod->plugin->type == nmsg_msgmod_type_transparent &&
	    msg->mod->plugin->pbdescr != NULL)
	{
		res = _nmsg_message_dup_protobuf(msg, &(msgdup->message));
		if (res != nmsg_res_success) {
			free(msgdup);
			return (NULL);
		}
	}

	/* initialize ->np */
	if (msg->np != NULL) {
		msgdup->np = malloc(sizeof(*msg->np));
		if (msgdup->np == NULL) {
			free(msgdup->message);
			free(msgdup);
			return (NULL);
		}
		memcpy(msgdup->np, msg->np, sizeof(*msg->np));

		if (msg->np->has_payload && msg->np->payload.data != NULL) {
			msgdup->np->payload.data = malloc(msg->np->payload.len);
			if (msgdup->np->payload.data == NULL) {
				free(msgdup->np);
				free(msgdup->message);
				free(msgdup);
				return (NULL);
			}
			memcpy(msgdup->np->payload.data, msg->np->payload.data,
			       msg->np->payload.len);
		}

		if (msgdup->np->base.n_unknown_fields != 0) {
			msgdup->np->base.n_unknown_fields = 0;
			msgdup->np->base.unknown_fields = NULL;
		}
	}

	return (msgdup);
}

struct nmsg_message *
_nmsg_message_from_payload(Nmsg__NmsgPayload *np) {
	struct nmsg_message *msg;

	/* allocate space */
	msg = calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	/* initialize ->mod */
	msg->mod = nmsg_msgmod_lookup(np->vid, np->msgtype);

	/* initialize ->message */
	msg->message = NULL;

	/* initialize ->np */
	msg->np = np;

	/* initialize ->msg_clos */
	if (msg->mod != NULL && msg->mod->plugin->msg_load != NULL)
		msg->mod->plugin->msg_load(msg, &msg->msg_clos);

	/* strip unknown fields */
	if (np->base.n_unknown_fields != 0) {
		unsigned i;

		for (i = 0; i < np->base.n_unknown_fields; i++)
			free(np->base.unknown_fields[i].data);

		free(np->base.unknown_fields);
		np->base.unknown_fields = NULL;
		np->base.n_unknown_fields = 0;
	}

	return (msg);
}

struct nmsg_message *
nmsg_message_from_raw_payload(unsigned vid, unsigned msgtype,
			      uint8_t *data, size_t sz,
			      const struct timespec *ts)
{
	nmsg_message_t msg;

	/* allocate message object */
	msg = calloc(1, sizeof(*msg));
	if (msg == NULL)
		return (NULL);

	/* allocate the NmsgPayload */
	msg->np = calloc(1, sizeof(*(msg->np)));
	if (msg->np == NULL) {
		free(msg);
		return (NULL);
	}

	/* initialize ->np */
	nmsg__nmsg_payload__init(msg->np);
	msg->np->base.n_unknown_fields = 0;
	msg->np->base.unknown_fields = NULL;
	msg->np->vid = vid;
	msg->np->msgtype = msgtype;
	msg->np->has_payload = true;
	msg->np->payload.data = data;
	msg->np->payload.len = sz;
	nmsg_message_set_time(msg, ts);

	/* initialize ->mod */
	msg->mod = nmsg_msgmod_lookup(vid, msgtype);

	return (msg);
}

#ifdef HAVE_YAJL
nmsg_res
nmsg_message_from_json(const char *json, nmsg_message_t *msg) {
	nmsg_res res;
	yajl_val node;

	yajl_val vname_v;
	const char *vname_path[] = { "vname", (const char *) 0 };
	yajl_val mname_v;
	const char *mname_path[] = { "mname", (const char *) 0 };
	struct nmsg_msgmod *mod;

	yajl_val source_v;
	const char *source_path[] = { "source", (const char *) 0 };

	yajl_val operator_v;
	const char *operator_path[] = { "operator", (const char *) 0 };

	yajl_val group_v;
	const char *group_path[] = { "group", (const char *) 0 };

	yajl_val time_v;
	const char *time_path[] = { "time", (const char *) 0 };
	struct timespec ts;

	yajl_val message_v;
	const char *message_path[] = { "message", (const char *) 0 };

	*msg = NULL;

	node = yajl_tree_parse(json, 0, 0);

	if (node == NULL)
		return (nmsg_res_parse_error);

	vname_v = yajl_tree_get(node, vname_path, yajl_t_string);
	mname_v = yajl_tree_get(node, mname_path, yajl_t_string);
	if (vname_v == NULL || mname_v == NULL) {
		res = (nmsg_res_parse_error);
		goto err;
	} else {
		char *vname, *mname;

		vname = YAJL_GET_STRING(vname_v);
		mname = YAJL_GET_STRING(mname_v);

		mod = nmsg_msgmod_lookup_byname(vname, mname);
		if (mod == NULL) {
			res = (nmsg_res_parse_error);
			goto err;
		}
	}

	*msg = nmsg_message_init(mod);
	if (*msg == NULL) {
		res = (nmsg_res_failure);
		goto err;
	}

	source_v = yajl_tree_get(node, source_path, yajl_t_any);
	if (source_v) {
		uint32_t source;

		if (YAJL_IS_STRING(source_v)) {
			sscanf(YAJL_GET_STRING(source_v), "%x", &source);
		} else if (YAJL_IS_INTEGER(source_v)) {
			source = YAJL_GET_INTEGER(source_v);
		} else {
			res = (nmsg_res_parse_error);
			goto err;
		}
		nmsg_message_set_source(*msg, source);
	}

	operator_v = yajl_tree_get(node, operator_path, yajl_t_any);
	if (operator_v) {
		uint32_t operator;

		if (YAJL_IS_STRING(operator_v)) {
			operator = nmsg_alias_by_value(nmsg_alias_operator, YAJL_GET_STRING(operator_v));
		} else if (YAJL_IS_INTEGER(operator_v)) {
			operator = YAJL_GET_INTEGER(operator_v);
		} else {
			res = (nmsg_res_parse_error);
			goto err;
		}
		nmsg_message_set_operator(*msg, operator);
	}

	group_v = yajl_tree_get(node, group_path, yajl_t_any);
	if (group_v) {
		uint32_t group;

		if (YAJL_IS_STRING(group_v)) {
			group = nmsg_alias_by_value(nmsg_alias_group, YAJL_GET_STRING(group_v));
		} else if (YAJL_IS_INTEGER(group_v)) {
			group = YAJL_GET_INTEGER(group_v);
		} else {
			res = (nmsg_res_parse_error);
			goto err;
		}
		nmsg_message_set_group(*msg, group);
	}

	time_v = yajl_tree_get(node, time_path, yajl_t_any);
	if (time_v) {
		if (YAJL_IS_STRING(time_v)) {
			struct tm tm;
			char * remainder;

			remainder = strptime(YAJL_GET_STRING(time_v), "%Y-%m-%d %T", &tm);
			if (remainder == NULL) {
				res = (nmsg_res_parse_error);
				goto err;
			}

			ts.tv_sec = timegm(&tm);

			if (sscanf(remainder, ".%ld", &ts.tv_nsec) == 0) {
				ts.tv_nsec = 0;
			}
		} else if (YAJL_IS_INTEGER(time_v)) {
			ts.tv_sec = YAJL_GET_INTEGER(time_v);
			ts.tv_nsec = 0;
		} else if (YAJL_IS_DOUBLE(time_v)) {
			nmsg_timespec_from_double(YAJL_GET_DOUBLE(time_v), &ts);
		} else {
			res = (nmsg_res_parse_error);
			goto err;
		}
	} else {
		nmsg_timespec_get(&ts);
	}
	nmsg_message_set_time(*msg, &ts);

	switch (mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		message_v = yajl_tree_get(node, message_path, yajl_t_object);
		if (message_v) {
			res = (_nmsg_msgmod_json_to_message(message_v, *msg));
			if (res != nmsg_res_success) {
				goto err;
			}
		} else {
			res = (nmsg_res_parse_error);
			goto err;
		}
		break;
	default:
		res = (nmsg_res_notimpl);
		goto err;
	}

	yajl_tree_free(node);

	return (nmsg_res_success);
err:
	if (*msg != NULL) {
		nmsg_message_destroy(msg);
	}

	yajl_tree_free(node);
	return (res);
}
#else /* HAVE_YAJL */
nmsg_res
nmsg_message_from_json(const char *json, nmsg_message_t *msg) {
	return (nmsg_res_notimpl);
}
#endif /* HAVE_YAJL */

nmsg_res
_nmsg_message_init_message(struct nmsg_message *msg) {
	if (msg->mod->plugin->type == nmsg_msgmod_type_transparent &&
	    msg->mod->plugin->pbdescr != NULL)
	{
		msg->message = calloc(1, msg->mod->plugin->pbdescr->sizeof_message);
		if (msg->message == NULL)
			return (nmsg_res_memfail);
		msg->message->descriptor = msg->mod->plugin->pbdescr;
	} else {
		msg->message = NULL;
	}
	return (nmsg_res_success);
}

nmsg_res
_nmsg_message_init_payload(struct nmsg_message *msg) {
	struct timespec ts;

	msg->np = malloc(sizeof(*msg->np));
	if (msg->np == NULL)
		return (nmsg_res_memfail);
	nmsg__nmsg_payload__init(msg->np);
	msg->np->vid = msg->mod->plugin->vendor.id;
	msg->np->msgtype = msg->mod->plugin->msgtype.id;
	nmsg_timespec_get(&ts);
	msg->np->time_sec = ts.tv_sec;
	msg->np->time_nsec = ts.tv_nsec;

	return (nmsg_res_success);
}

void
nmsg_message_destroy(struct nmsg_message **msg) {
	if ((*msg)->mod != NULL && (*msg)->mod->plugin->msg_fini != NULL)
		(*msg)->mod->plugin->msg_fini(*msg, (*msg)->msg_clos);

	if ((*msg)->message != NULL) {
		protobuf_c_message_free_unpacked((*msg)->message, NULL);
		(*msg)->message = NULL;
	}
	if ((*msg)->np != NULL)
		_nmsg_payload_free(&(*msg)->np);

	nmsg_message_free_allocations(*msg);

	free(*msg);
	*msg = NULL;
}

nmsg_res
_nmsg_message_deserialize(struct nmsg_message *msg) {
	if (msg->message != NULL)
		return (nmsg_res_success);

	if (msg->np != NULL) {
		if (msg->mod == NULL || msg->np->has_payload == 0)
			return (nmsg_res_failure);
		msg->message = protobuf_c_message_unpack(msg->mod->plugin->pbdescr, NULL,
							 msg->np->payload.len,
							 msg->np->payload.data);
		if (msg->message == NULL)
			return (nmsg_res_memfail);
		return (nmsg_res_success);
	}
	return (nmsg_res_failure);
}

nmsg_res
_nmsg_message_serialize(struct nmsg_message *msg) {
	ProtobufCBufferSimple sbuf = {0};
	nmsg_res res;
	size_t sz;

	if (msg->message != NULL &&
	    (msg->updated || msg->np == NULL))
	{
		if (msg->np == NULL) {
			res = _nmsg_message_init_payload(msg);
			if (res != nmsg_res_success)
				return (res);
		}

		sbuf.base.append = protobuf_c_buffer_simple_append;
		sbuf.len = 0;
		sbuf.data = malloc(1024);
		if (sbuf.data == NULL)
			return (nmsg_res_memfail);
		sbuf.must_free_data = 1;
		sbuf.alloced = 1024;

		sz = protobuf_c_message_pack_to_buffer((ProtobufCMessage *) msg->message,
						       (ProtobufCBuffer *) &sbuf);
		if (msg->np->payload.data != NULL)
			free(msg->np->payload.data);

		msg->np->has_payload = true;
		msg->np->payload.data = sbuf.data;
		msg->np->payload.len = sz;

		msg->updated = false;
	}

	return (nmsg_res_success);
}

nmsg_res
nmsg_message_to_pres(struct nmsg_message *msg, char **pres, const char *endline) {
	if (msg->mod == NULL)
		return (nmsg_res_failure);
	switch (msg->mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_message_payload_to_pres(msg, pres, endline));
	case nmsg_msgmod_type_opaque:
		if (msg->mod->plugin->payload_to_pres != NULL)
			return (msg->mod->plugin->payload_to_pres(msg->np, pres, endline));
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_message_to_json(nmsg_message_t msg, char **json) {
	if (msg->mod == NULL)
		return (nmsg_res_failure);
	switch (msg->mod->plugin->type) {
	case nmsg_msgmod_type_transparent:
		return (_nmsg_message_payload_to_json(msg, json));
	case nmsg_msgmod_type_opaque:
		return (nmsg_res_notimpl);
	default:
		return (nmsg_res_notimpl);
	}
}

nmsg_res
nmsg_message_add_allocation(struct nmsg_message *msg, void *ptr) {
	void *tmp;

	msg->n_allocs += 1;
	tmp = msg->allocs;
	msg->allocs = realloc(msg->allocs, sizeof(ptr) * msg->n_allocs);
	if (msg->allocs == NULL) {
		msg->allocs = tmp;
		msg->n_allocs -= 1;
		return (nmsg_res_memfail);
	}
	msg->allocs[msg->n_allocs - 1] = ptr;

	return (nmsg_res_success);
}

void
nmsg_message_free_allocations(struct nmsg_message *msg) {
	size_t n;

	for (n = 0; n < msg->n_allocs; n++)
		free(msg->allocs[n]);
	free(msg->allocs);
	msg->allocs = NULL;
	msg->n_allocs = 0;
}

nmsg_msgmod_t
nmsg_message_get_msgmod(nmsg_message_t msg) {
	return (msg->mod);
}

int32_t
nmsg_message_get_vid(nmsg_message_t msg) {
	return (msg->np->vid);
}

int32_t
nmsg_message_get_msgtype(nmsg_message_t msg) {
	return (msg->np->msgtype);
}

void *
nmsg_message_get_payload(nmsg_message_t msg) {
	nmsg_res res;

	res = _nmsg_message_deserialize(msg);
	assert(res == nmsg_res_success && msg->message != NULL);
	return ((void *) msg->message);
}

size_t
nmsg_message_get_payload_size(nmsg_message_t msg) {

	assert(msg->np != NULL);
	return (_nmsg_payload_size(msg->np));
}

void
nmsg_message_update(nmsg_message_t msg) {
	msg->updated = true;
}

void
nmsg_message_compact_payload(nmsg_message_t msg) {
	if (msg->message != NULL) {
		protobuf_c_message_free_unpacked(msg->message, NULL);
		msg->message = NULL;
	}
}

void
nmsg_message_get_time(nmsg_message_t msg, struct timespec *ts) {
	ts->tv_sec = msg->np->time_sec;
	ts->tv_nsec = msg->np->time_nsec;
}

void
nmsg_message_set_time(nmsg_message_t msg, const struct timespec *ts) {
	if (ts == NULL) {
		struct timespec now;
		nmsg_timespec_get(&now);
		nmsg_message_set_time(msg, &now);
	} else {
		msg->np->time_sec = ts->tv_sec;
		msg->np->time_nsec = ts->tv_nsec;
	}
}

uint32_t
nmsg_message_get_source(nmsg_message_t msg) {
	if (msg->np->has_source)
		return (msg->np->source);
	return (0);
}

uint32_t
nmsg_message_get_operator(nmsg_message_t msg) {
	if (msg->np->has_operator_)
		return (msg->np->operator_);
	return (0);
}

uint32_t
nmsg_message_get_group(nmsg_message_t msg) {
	if (msg->np->has_group)
		return (msg->np->group);
	return (0);
}

void
nmsg_message_set_source(nmsg_message_t msg, uint32_t source) {
	if (source == 0) {
		msg->np->has_source = 0;
	} else {
		msg->np->has_source = 1;
		msg->np->source = source;
	}
}

void
nmsg_message_set_operator(nmsg_message_t msg, uint32_t operator) {
	if (operator == 0) {
		msg->np->has_operator_ = 0;
	} else {
		msg->np->has_operator_ = 1;
		msg->np->operator_ = operator;
	}
}

void
nmsg_message_set_group(nmsg_message_t msg, uint32_t group) {
	if (group == 0) {
		msg->np->has_group = 0;
	} else {
		msg->np->has_group = 1;
		msg->np->group = group;
	}
}
