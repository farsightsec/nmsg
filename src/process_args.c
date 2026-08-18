/*
 * Copyright (c) 2023-2024, 2026 DomainTools LLC
 * Copyright (c) 2008-2015, 2019, 2021 by Farsight Security, Inc.
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

#include <sys/types.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "nmsgtool.h"

static nmsg_res
droproot(nmsgtool_ctx *c, FILE *fp_pidfile)
{
	struct passwd *pw = NULL;

	if (c->username == NULL)
		return (nmsg_res_success);

	pw = getpwnam(c->username);
	if (pw == NULL) {
		fprintf(stderr, "%s: username %s does not exist\n",
			argv_program, c->username);
		return (nmsg_res_failure);
	}

	if (fp_pidfile != NULL) {
		int fd = fileno(fp_pidfile);
		if (fd != -1) {
			if (fchown(fd, pw->pw_uid, pw->pw_gid) != 0) {
				fprintf(stderr,"%s: fchown() on pid file failed: %s\n", argv_program,
					strerror(errno));
				return (nmsg_res_failure);
			}
		}
	}

	if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
	    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
	{
		fprintf(stderr, "%s: unable to change to user %s\n",
			argv_program, c->username);
		return (nmsg_res_failure);
	}

	if (c->debug >= 2)
		fprintf(stderr, "%s: switched to user %s\n",
			argv_program, c->username);

	return (nmsg_res_success);
}

/* Convert string to non-zero unsigned 32 bit val, returning zero on failure. */
static uint32_t
read_uint32_nz(const char *str)
{
	char *t;
	unsigned long val;

	val = strtoul(str, &t, 0);
	if (*t != '\0')
		return 0;
	else if (val > UINT32_MAX)
		return 0;

	return (uint32_t)val;
}

static nmsg_res
process_args_loop(nmsgtool_ctx *c, argv_array_t *arry, nmsg_res (*f)(nmsgtool_ctx *, const char *))
{
	nmsg_res res = nmsg_res_success;

	for (int i = 0; i < ARGV_ARRAY_COUNT(*arry); i++) {
		res = f(c, *ARGV_ARRAY_ENTRY_P(*arry, char *, i));
		if (res != nmsg_res_success) {
			break;
		}
	}

	return (res);
}

static nmsg_res
process_args_loop_mod(nmsgtool_ctx *c, argv_array_t *arry, nmsg_res (*f)(nmsgtool_ctx *, nmsg_msgmod_t, const char *),
	nmsg_msgmod_t *mod)
{
	nmsg_res res = nmsg_res_success;

	for (int i = 0; i < ARGV_ARRAY_COUNT(*arry); i++) {
		res = f(c, *mod, *ARGV_ARRAY_ENTRY_P(*arry, char *, i));
		if (res != nmsg_res_success) {
			break;
		}
	}

	return (res);
}

nmsg_res
process_args(nmsgtool_ctx *c)
{
	char *t;
	FILE *fp_pidfile = NULL;
	nmsg_msgmod_t mod = NULL;
	nmsg_res res;

	if (c->endline == NULL)
		c->endline_str = strdup("\n");
	else
		c->endline_str = unescape(c->endline);

	if (c->mtu == 0)
		c->mtu = NMSG_WBUFSZ_JUMBO;

	if (c->vname == NULL && c->mname != NULL)
		c->vname = "base";

	if (c->vname != NULL) {
		if (c->mname == NULL) {
			fprintf(stderr, "%s: usage error: -V requires -T\n", argv_program);
			return (nmsg_res_failure);
		}
		c->vid = nmsg_msgmod_vname_to_vid(c->vname);
		if (c->vid == 0) {
			fprintf(stderr, "%s: usage error: invalid vendor ID\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: input vendor = %s\n",
				argv_program, c->vname);
	}
	if (c->mname != NULL) {
		if (c->vname == NULL) {
			fprintf(stderr, "%s: usage error: -T requires -V\n", argv_program);
			return (nmsg_res_failure);
		}
		c->msgtype = nmsg_msgmod_mname_to_msgtype(c->vid, c->mname);
		if (c->msgtype == 0) {
			fprintf(stderr, "%s: invalid message type\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: input msgtype = %s\n",
				argv_program, c->mname);
	}
	if (c->debug < 1)
		c->debug = 1;
	if (c->debug > 0)
		nmsg_io_set_debug(c->io, c->debug);
	if (c->count > 0)
		nmsg_io_set_count(c->io, c->count);
	if (c->interval > 0)
		nmsg_io_set_interval(c->io, c->interval);
	if (c->interval_randomized == true)
		nmsg_io_set_interval_randomized(c->io, true);
	if (c->mirror == true)
		nmsg_io_set_output_mode(c->io, nmsg_io_output_mode_mirror);

	/* bpf string */
	if (c->bpfstr == NULL) {
		t = getenv("NMSG_BPF");
		if (t != NULL)
			c->bpfstr = strdup(t);
	}

	/* kicker command */
	if (c->kicker == NULL) {
		t = getenv("NMSG_KICKER");
		if (t != NULL)
			c->kicker = strdup(t);
	}

#if defined(HAVE_LIBRDKAFKA)
	/* kafka key */
	if (c->kafka_key_field == NULL) {
		t = getenv("NMSG_KAFKA_KEY");
		if (t != NULL)
			c->kafka_key_field = t;
	}
#endif /* defined(HAVE_LIBRDKAFKA) */

	/* set source, operator, group */
	if (c->set_source_str != NULL) {
		c->set_source = read_uint32_nz(c->set_source_str);
		if (c->set_source == 0) {
			fprintf(stderr, "%s: usage error: invalid source ID\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg source set to %#.08x\n",
				argv_program, c->set_source);
	}
	if (c->set_operator_str != NULL) {
		c->set_operator = nmsg_alias_by_value(nmsg_alias_operator,
						      c->set_operator_str);
		if (c->set_operator == 0)
			c->set_operator = read_uint32_nz(c->set_operator_str);
		if (c->set_operator == 0) {
			fprintf(stderr, "%s: usage error: unknown operator name\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg operator set to '%s' (%u)\n",
				argv_program,
				c->set_operator_str,
				c->set_operator);
	}

	if (c->set_group_str != NULL) {
		c->set_group = nmsg_alias_by_value(nmsg_alias_group,
						   c->set_group_str);
		if (c->set_group == 0)
			c->set_group = read_uint32_nz(c->set_group_str);
		if (c->set_group == 0) {
			fprintf(stderr, "%s: usage error: unknown group name\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg group set to '%s' (%u)\n",
				argv_program,
				c->set_group_str,
				c->set_group);
	}

	/* get source, operator, group */
	if (c->get_source_str != NULL) {
		c->get_source = read_uint32_nz(c->get_source_str);
		if (c->get_source == 0) {
			fprintf(stderr, "%s: usage error: invalid filter source ID\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg source filter set to "
					"%#.08x\n",
				argv_program, c->get_source);
	}

	if (c->get_operator_str != NULL) {
		c->get_operator = nmsg_alias_by_value(nmsg_alias_operator,
						      c->get_operator_str);
		if (c->get_operator == 0)
			c->get_operator = read_uint32_nz(c->get_operator_str);
		if (c->get_operator == 0) {
			fprintf(stderr, "%s: usage error: unknown filter operator name\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg filter operator set to "
					"'%s' (%u)\n",
				argv_program,
				c->get_operator_str,
				c->get_operator);
	}

	if (c->get_group_str != NULL) {
		c->get_group = nmsg_alias_by_value(nmsg_alias_group,
						   c->get_group_str);
		if (c->get_group == 0)
			c->get_group = read_uint32_nz(c->get_group_str);
		if (c->get_group == 0) {
			fprintf(stderr, "%s: usage error: unknown filter group name\n", argv_program);
			return (nmsg_res_failure);
		}
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg filter group set to "
					"'%s' (%u)\n",
				argv_program,
				c->get_group_str,
				c->get_group);
	}

	/* -V, -T sanity check */
	if (ARGV_ARRAY_COUNT(c->r_pcapfile) > 0 ||
	    ARGV_ARRAY_COUNT(c->r_pcapif) > 0)
	{
		if (c->vname == NULL || c->mname == NULL) {
			fprintf(stderr, "%s: usage error: reading pcap data requires -V, -T\n", argv_program);
			return (nmsg_res_failure);
		}
		mod = nmsg_msgmod_lookup(c->vid, c->msgtype);
		if (mod == NULL) {
			fprintf(stderr, "%s: usage error: unknown msgmod\n", argv_program);
			return (nmsg_res_failure);
		}
	}

	/* pcap interface inputs */
	res = process_args_loop_mod(c, &c->r_pcapif, add_pcapif_input, &mod);
	if (res != nmsg_res_success) {
		return (res);
	}

	/* open pidfile if necessary */
	if (c->pidfile != NULL)
		fp_pidfile = pidfile_open(c->pidfile);
	else
		fp_pidfile = NULL;

	/* drop privileges */
	if (c->username != NULL) {
		res = droproot(c, fp_pidfile);
		if (res != nmsg_res_success) {
			return (res);
		}
	}

	/* pcap file inputs */
	res = process_args_loop_mod(c, &c->r_pcapfile, add_pcapfile_input, &mod);
	if (res != nmsg_res_success) {
		return (res);
	}

	/* ZMQ context */
	if (ARGV_ARRAY_COUNT(c->r_zsock) > 0 ||
	    ARGV_ARRAY_COUNT(c->w_zsock) > 0 ||
	    ARGV_ARRAY_COUNT(c->r_zchannel) > 0)
	{
#ifdef HAVE_LIBZMQ
		c->zmq_ctx = zmq_ctx_new();
		if (c->zmq_ctx == NULL) {
			fprintf(stderr, "%s: zmq_ctx_new() failed: %s\n",
				argv_program, strerror(errno));
			return (nmsg_res_failure);
		}
#else /* HAVE_LIBZMQ */
		fprintf(stderr, "%s: Error: compiled without libzmq support\n",
			argv_program);
		return (nmsg_res_failure);
#endif /* HAVE_LIBZMQ */
	}

	for (int i = 0; i < ARGV_ARRAY_COUNT(c->r_channel); i++) {
		char *ch;
		char **alias = NULL;
		int num_aliases;

		ch = *ARGV_ARRAY_ENTRY_P(c->r_channel, char *, i);
		if (c->debug >= 2)
			fprintf(stderr, "%s: looking up channel '%s'\n", argv_program, ch);
		num_aliases = nmsg_chalias_lookup(ch, &alias);
		if (num_aliases <= 0) {
			fprintf(stderr, "%s: usage error: channel alias lookup failed\n", argv_program);
			return (nmsg_res_failure);
		}
		for (int j = 0; j < num_aliases; j++) {
			if (strstr(alias[j], "://")) {
				fprintf(stderr, "%s: usage error: channel alias appears to be a ZeroMQ endpoint\n",
					argv_program);
				return (nmsg_res_failure);
			}
			res = add_sock_input(c, alias[j]);
			if (res != nmsg_res_success) {
				return (res);
			}
		}
		nmsg_chalias_free(&alias);
	}

	for (int i = 0; i < ARGV_ARRAY_COUNT(c->r_zchannel); i++) {
		char *ch;
		char **alias = NULL;
		int num_aliases;

		ch = *ARGV_ARRAY_ENTRY_P(c->r_zchannel, char *, i);
		if (c->debug >= 2)
			fprintf(stderr, "%s: looking up zchannel '%s'\n", argv_program, ch);
		num_aliases = nmsg_chalias_lookup(ch, &alias);
		if (num_aliases <= 0) {
			fprintf(stderr, "%s: usage error: zchannel alias lookup failed\n", argv_program);
			return (nmsg_res_failure);
		}
		for (int j = 0; j < num_aliases; j++) {
			if (!strstr(alias[j], "://")) {
				fprintf(stderr, "%s: usage error: zchannel alias needs to be a ZeroMQ endpoint\n",
					argv_program);
				return (nmsg_res_failure);
			}
			res = add_zsock_input(c, alias[j]);
			if (res != nmsg_res_success) {
				return (res);
			}
		}
		nmsg_chalias_free(&alias);
	}

	/* filter policy */
	if (ARGV_ARRAY_COUNT(c->filters) > 0 && c->filter_policy != NULL) {
		if (strcasecmp(c->filter_policy, "ACCEPT") == 0) {
			if (c->debug >= 2)
				fprintf(stderr, "%s: setting default filter policy to ACCEPT\n",
					argv_program);
			nmsg_io_set_filter_policy(c->io, nmsg_filter_message_verdict_ACCEPT);
		} else if (strcasecmp(c->filter_policy, "DROP") == 0) {
			if (c->debug >= 2)
				fprintf(stderr, "%s: setting default filter policy to DROP\n",
					argv_program);
			nmsg_io_set_filter_policy(c->io, nmsg_filter_message_verdict_DROP);
		} else {
			fprintf(stderr, "%s: unknown filter policy '%s'\n",
				argv_program, c->filter_policy);
			return (nmsg_res_failure);
		}
	}

	/* nmsg inputs and outputs that create files */
	res = process_args_loop(c, &c->r_sock, add_sock_input);
	if (res != nmsg_res_success) {
		return (res);
	}

	res = process_args_loop(c, &c->w_sock, add_sock_output);
	if (res != nmsg_res_success) {
		return (res);
	}
	res = process_args_loop(c, &c->r_zsock, add_zsock_input);
	if (res != nmsg_res_success) {
		return (res);
	}
	res = process_args_loop(c, &c->w_zsock, add_zsock_output);
	if (res != nmsg_res_success) {
		return (res);
	}
	res = process_args_loop(c, &c->r_kafka, add_kafka_input);
	if (res != nmsg_res_success) {
		return (res);
	}
	res = process_args_loop(c, &c->w_kafka, add_kafka_output);
	if (res != nmsg_res_success) {
		return (res);
	}
	res = process_args_loop(c, &c->r_nmsg, add_file_input);
	if (res != nmsg_res_success) {
		return (res);
	}

	/* json input */
	res = process_args_loop(c, &c->r_json, add_json_input);
	if (res != nmsg_res_success) {
		return (res);
	}

	/* stats modules */
	res = process_args_loop(c, &c->statsmods, add_stats_module);
	if (res != nmsg_res_success) {
		return (res);
	}

	/* filter modules */
	res = process_args_loop(c, &c->filters, add_filter_module);
	if (res != nmsg_res_success) {
		return (res);
	}

	/* validation */
	if (c->n_inputs == 0) {
		fprintf(stderr, "%s: usage error: no data sources specified (-h for more help)\n", argv_program);
		return (nmsg_res_failure);
	}

	/* file outputs: deferred until inputs are validated */
	res = process_args_loop(c, &c->w_nmsg, add_file_output);
	if (res != nmsg_res_success) {
		return (res);
	}
	res = process_args_loop(c, &c->w_pres, add_pres_output);
	if (res != nmsg_res_success) {
		return (res);
	}
	res = process_args_loop(c, &c->w_json, add_json_output);
	if (res != nmsg_res_success) {
		return (res);
	}

	if (c->n_outputs == 0) {
		/* implicit "-o -" */
		res = add_pres_output(c, "-");
		if (res != nmsg_res_success) {
			return (res);
		}
	}

	/* daemonize if necessary */
	if (c->daemon) {
		if (!daemonize()) {
			fprintf(stderr, "%s: unable to daemonize: %s\n", argv_program, strerror(errno));
			return (nmsg_res_failure);
		}
	}

	/* write pidfile if necessary */
	if (c->pidfile != NULL && fp_pidfile != NULL)
		pidfile_write(fp_pidfile);

	return (nmsg_res_success);
}
