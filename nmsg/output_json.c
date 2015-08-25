/*
 * Copyright (c) 2008-2012 by Farsight Security, Inc.
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
#include <arpa/inet.h>

/* Internal functions. */

#ifdef HAVE_YAJL

#define add_yajl_string(g, s) do {                                              \
	yajl_gen_status g_status;                                               \
	g_status = yajl_gen_string(g, (const unsigned  char *) s, strlen(s));   \
	assert(g_status == yajl_gen_status_ok);                                 \
} while (0)

static void
callback_print_yajl_ubuf(void *ctx, const char *str, size_t len)
{
        ubuf *u = (ubuf *) ctx;
        ubuf_append(u, (const uint8_t *) str, len);
}

nmsg_res
_output_json_write(nmsg_output_t output, nmsg_message_t msg) {
	Nmsg__NmsgPayload *np;
	nmsg_res res;
	yajl_gen g;
	yajl_gen_status status;
	int yajl_rc;
	ubuf *u;
	uint8_t *s = NULL;
	size_t u_len;
	const char * ntop_status;

	size_t field_idx, n_fields;
	const char *field_name;
	nmsg_msgmod_field_type field_type;
	unsigned field_flags;

	size_t val_idx;
        unsigned val_enum;
        const char *str_enum;
        int val_bool;
	char str_ip[INET_ADDRSTRLEN];
	char str_ip6[INET6_ADDRSTRLEN];
        uint32_t val_uint32;
        uint64_t val_uint64;
        int32_t val_int32;
        int64_t val_int64;
        double val_double;
        const uint8_t *data;
        size_t data_len;

	u = ubuf_init(256);

	np = msg->np;

	/* lock output */
	pthread_mutex_lock(&output->json->lock);

	g = yajl_gen_alloc(NULL);
	assert (g != NULL);

	yajl_rc = yajl_gen_config(g, yajl_gen_print_callback, callback_print_yajl_ubuf, u);
	assert (yajl_rc != 0);

	status = yajl_gen_map_open(g);
	assert(status == yajl_gen_status_ok);
	
	add_yajl_string(g, "time_sec");
	status = yajl_gen_integer(g, np->time_sec);
	assert(status == yajl_gen_status_ok);

	add_yajl_string(g, "time_nsec");
	status = yajl_gen_integer(g, np->time_nsec);
	assert(status == yajl_gen_status_ok);

	add_yajl_string(g, "vid");
	status = yajl_gen_integer(g, np->vid);
	assert(status == yajl_gen_status_ok);

	add_yajl_string(g, "msgtype");
	status = yajl_gen_integer(g, np->msgtype);
	assert(status == yajl_gen_status_ok);

	if (np->has_source) {
		add_yajl_string(g, "source");
		status = yajl_gen_integer(g, np->source);
		assert(status == yajl_gen_status_ok);
	}
	
	if (np->has_operator_) {
		add_yajl_string(g, "operator");
		status = yajl_gen_integer(g, np->operator_);
		assert(status == yajl_gen_status_ok);
	}
	
	if (np->has_group) {
		add_yajl_string(g, "group");
		status = yajl_gen_integer(g, np->group);
		assert(status == yajl_gen_status_ok);
	}

	add_yajl_string(g, "message");

	status = yajl_gen_map_open(g);
	assert(status == yajl_gen_status_ok);

	res = nmsg_message_get_num_fields(msg, &n_fields);
	if (res != nmsg_res_success) {
		// raise Exception, 'nmsg_message_get_num_fields() failed'
	}

	for (field_idx = 0; field_idx < n_fields; field_idx++) {
		res = nmsg_message_get_field_name(msg, field_idx, &field_name);
		if (res != nmsg_res_success) {
			continue;
		}

		/* Ensure that there is at least one value */
		res = nmsg_message_get_field_by_idx(msg, field_idx, 0, (void **) &data, &data_len);
		if (res == nmsg_res_success) {
			status = yajl_gen_string(g, (unsigned char *) field_name, strlen(field_name));
			assert(status == yajl_gen_status_ok);
		} else {
			continue;
		}

		res = nmsg_message_get_field_flags_by_idx(msg, field_idx, &field_flags);
		if (res != nmsg_res_success) {
			status = yajl_gen_null(g);
			assert(status == yajl_gen_status_ok);
			continue;
		}

		res = nmsg_message_get_field_type_by_idx(msg, field_idx, &field_type);
		if (res != nmsg_res_success) {
			status = yajl_gen_null(g);
			assert(status == yajl_gen_status_ok);
			continue;
		}

		if (field_flags & NMSG_MSGMOD_FIELD_REPEATED) {
			status = yajl_gen_array_open(g);
			assert(status == yajl_gen_status_ok);
		}

		val_idx = 0;

		while (1) {
			res = nmsg_message_get_field_by_idx(msg, field_idx, val_idx, (void **) &data, &data_len);
			if (res != nmsg_res_success) {
				break;
			}
			val_idx++;

			switch(field_type) {
				case nmsg_msgmod_ft_enum:
					val_enum = data[0]; // TODO bounds check?
					res = nmsg_message_enum_value_to_name_by_idx(msg, field_idx, val_enum, &str_enum);
					if (res == nmsg_res_success) {
						status = yajl_gen_string(g, (const unsigned char*) str_enum, strlen(str_enum));
						assert(status == yajl_gen_status_ok);
					} else {
						status = yajl_gen_integer(g, val_enum);
						assert(status == yajl_gen_status_ok);
					}
					break;
				case nmsg_msgmod_ft_bytes:
					status = yajl_gen_string(g, (const unsigned char*) data, data_len);
					assert(status == yajl_gen_status_ok);
					break;
				case nmsg_msgmod_ft_string:
				case nmsg_msgmod_ft_mlstring:
					if (data_len > 0 && data[data_len-1]) {
						data_len--;
					}
					status = yajl_gen_string(g, (const unsigned char*)data, data_len);
					assert(status == yajl_gen_status_ok);
					break;
				case nmsg_msgmod_ft_ip:
					if (data_len == 4) {
						ntop_status = inet_ntop(AF_INET, data, str_ip, sizeof(str_ip));
						assert(ntop_status != NULL);
						status = yajl_gen_string(g, (const unsigned char*)str_ip, strlen(str_ip));
						assert(status == yajl_gen_status_ok);
					} else if (data_len == 16) {
						ntop_status = inet_ntop(AF_INET6, data, str_ip6, sizeof(str_ip6));
						assert(ntop_status != NULL);
						status = yajl_gen_string(g, (const unsigned char*)str_ip, strlen(str_ip));
						assert(status == yajl_gen_status_ok);
					} else {
						status = yajl_gen_number(g, (const char*)data, data_len);
						assert(status == yajl_gen_status_ok);
					}
					break;
				case nmsg_msgmod_ft_uint16:
				case nmsg_msgmod_ft_uint32:
					val_uint32 = ((uint32_t *)data)[0];
					status = yajl_gen_integer(g, val_uint32);
					assert(status == yajl_gen_status_ok);
					break;
				case nmsg_msgmod_ft_uint64:
					val_uint64 = ((uint64_t *)data)[0];
					status = yajl_gen_integer(g, val_uint64);
					assert(status == yajl_gen_status_ok);
					break;
				case nmsg_msgmod_ft_int16:
				case nmsg_msgmod_ft_int32:
					val_int32 = ((int32_t *)data)[0];
					status = yajl_gen_integer(g, val_int32);
					assert(status == yajl_gen_status_ok);
					break;
				case nmsg_msgmod_ft_int64:
					val_int64 = ((int64_t *)data)[0];
					status = yajl_gen_integer(g, val_int64);
					assert(status == yajl_gen_status_ok);
					break;
				case nmsg_msgmod_ft_double:
					val_double = ((double *)data)[0];
					status = yajl_gen_double(g, val_double);
					assert(status == yajl_gen_status_ok);
					break;
				case nmsg_msgmod_ft_bool:
					val_bool = ((int *)data)[0];
					status = yajl_gen_bool(g, val_bool);
					assert(status == yajl_gen_status_ok);
					break;
				default:
					status = yajl_gen_null(g);
					assert(status == yajl_gen_status_ok);
					break;

			}

			if (! (field_flags & NMSG_MSGMOD_FIELD_REPEATED)) {
				break;
			}
		}

		if (field_flags & NMSG_MSGMOD_FIELD_REPEATED) {
			status = yajl_gen_array_close(g);
			assert(status == yajl_gen_status_ok);
		}

	}

	status = yajl_gen_map_close(g);
	assert(status == yajl_gen_status_ok);

	status = yajl_gen_map_close(g);
	assert(status == yajl_gen_status_ok);

	yajl_gen_reset(g, "\n");

	ubuf_cterm(u);
	ubuf_detach(u, &s, &u_len);
	ubuf_destroy(&u);

	fwrite(s, sizeof(uint8_t), u_len, output->pres->fp);
	free(s);
        if (output->pres->flush)
                fflush(output->pres->fp);

	if (g != NULL) {
		yajl_gen_free(g);
	}

	/* unlock output */
	pthread_mutex_unlock(&output->json->lock);

	return (nmsg_res_success);
}
#else /* HAVE_YAJL */
nmsg_res
_output_json_write(nmsg_output_t output, nmsg_message_t msg) {
	return (nmsg_res_notimpl);
}
#endif /* HAVE_YAJL */
