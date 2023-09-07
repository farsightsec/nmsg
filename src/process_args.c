/*
 * Copyright (c) 2023 DomainTools LLC
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

#include "nmsgtool.h"

static void
droproot(nmsgtool_ctx *c, FILE *fp_pidfile) {
	struct passwd *pw = NULL;

	if (c->username == NULL)
		return;

	pw = getpwnam(c->username);
	if (pw == NULL) {
		fprintf(stderr, "%s: username %s does not exist\n",
			argv_program, c->username);
		exit(1);
	}

	if (fp_pidfile != NULL) {
		int fd = fileno(fp_pidfile);
		if (fd != -1) {
			if (fchown(fd, pw->pw_uid, pw->pw_gid) != 0) {
				fprintf(stderr,"%s: fchown() on pid file failed: %s\n", argv_program, strerror(errno));
			}
		}
	}

	if (initgroups(pw->pw_name, pw->pw_gid) != 0 ||
	    setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
	{
		fprintf(stderr, "%s: unable to change to user %s\n",
			argv_program, c->username);
		exit(1);
	}

	if (c->debug >= 2)
		fprintf(stderr, "%s: switched to user %s\n",
			argv_program, c->username);
}

void
process_args(nmsgtool_ctx *c) {
	char *t;
	FILE *fp_pidfile = NULL;
	nmsg_msgmod_t mod = NULL;

	if (c->help)
		usage(NULL);

	if (c->version) {
#ifdef HAVE_LIBZMQ
		fprintf(stderr, "%s: version %s\n", argv_program, PACKAGE_VERSION);
#else /* HAVE_LIBZMQ */
		fprintf(stderr, "%s: version %s (without libzmq support)\n",
			argv_program, PACKAGE_VERSION);
#endif /* HAVE_LIBZMQ */
		exit(EXIT_SUCCESS);
	}

	if (c->endline == NULL)
		c->endline_str = strdup("\n");
	else
		c->endline_str = unescape(c->endline);

	if (c->mtu == 0)
		c->mtu = NMSG_WBUFSZ_JUMBO;

	if (c->vname == NULL && c->mname != NULL)
		c->vname = "base";

	if (c->vname != NULL) {
		if (c->mname == NULL)
			usage("-V requires -T");
		c->vid = nmsg_msgmod_vname_to_vid(c->vname);
		if (c->vid == 0)
			usage("invalid vendor ID");
		if (c->debug >= 2)
			fprintf(stderr, "%s: input vendor = %s\n",
				argv_program, c->vname);
	}
	if (c->mname != NULL) {
		if (c->vname == NULL)
			usage("-T requires -V");
		c->msgtype = nmsg_msgmod_mname_to_msgtype(c->vid, c->mname);
		if (c->msgtype == 0)
			usage("invalid message type");
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

	/* set source, operator, group */
	if (c->set_source_str != NULL) {
		c->set_source = (unsigned) strtoul(c->set_source_str, &t, 0);
		if (*t != '\0')
			usage("invalid source ID");
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg source set to %#.08x\n",
				argv_program, c->set_source);
	}

	if (c->set_operator_str != NULL) {
		c->set_operator = nmsg_alias_by_value(nmsg_alias_operator,
						      c->set_operator_str);
		if (c->set_operator == 0)
			usage("unknown operator name");
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
			usage("unknown group name");
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg group set to '%s' (%u)\n",
				argv_program,
				c->set_group_str,
				c->set_group);
	}

	/* get source, operator, group */
	if (c->get_source_str != NULL) {
		c->get_source = (unsigned) strtoul(c->get_source_str, &t, 0);
		if (*t != '\0')
			usage("invalid filter source ID");
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg source filter set to "
					"%#.08x\n",
				argv_program, c->get_source);
	}

	if (c->get_operator_str != NULL) {
		c->get_operator = nmsg_alias_by_value(nmsg_alias_operator,
						      c->get_operator_str);
		if (c->get_operator == 0)
			usage("unknown filter operator name");
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
			usage("unknown filter group name");
		if (c->debug >= 2)
			fprintf(stderr, "%s: nmsg filter group set to "
					"'%s' (%u)\n",
				argv_program,
				c->get_group_str,
				c->get_group);
	}

	/* -V, -T sanity check */
	if (ARGV_ARRAY_COUNT(c->r_pres) > 0 ||
	    ARGV_ARRAY_COUNT(c->r_pcapfile) > 0 ||
	    ARGV_ARRAY_COUNT(c->r_pcapif) > 0)
	{
		if (c->vname == NULL || c->mname == NULL)
			usage("reading presentation or pcap data requires "
			      "-V, -T");
		mod = nmsg_msgmod_lookup(c->vid, c->msgtype);
		if (mod == NULL)
			usage("unknown msgmod");
	}

#define process_args_loop(arry, func) do { \
	for (int i = 0; i < ARGV_ARRAY_COUNT(arry); i++) \
		func(c, *ARGV_ARRAY_ENTRY_P(arry, char *, i)); \
} while(0)

#define process_args_loop_mod(arry, func, mod) do { \
	for (int i = 0; i < ARGV_ARRAY_COUNT(arry); i++) \
		func(c, mod, *ARGV_ARRAY_ENTRY_P(arry, char *, i)); \
} while(0)

	/* pcap interface inputs */
	process_args_loop_mod(c->r_pcapif, add_pcapif_input, mod);

	/* open pidfile if necessary */
	if (c->pidfile != NULL)
		fp_pidfile = pidfile_open(c->pidfile);
	else
		fp_pidfile = NULL;

	/* drop privileges */
	if (c->username != NULL)
		droproot(c, fp_pidfile);

	/* pcap file inputs */
	process_args_loop_mod(c->r_pcapfile, add_pcapfile_input, mod);

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
			exit(EXIT_FAILURE);
		}
#else /* HAVE_LIBZMQ */
		fprintf(stderr, "%s: Error: compiled without libzmq support\n",
			argv_program);
		exit(EXIT_FAILURE);
#endif /* HAVE_LIBZMQ */
	}

	/* nmsg inputs and outputs */
	process_args_loop(c->r_sock, add_sock_input);
	process_args_loop(c->w_sock, add_sock_output);
	process_args_loop(c->r_zsock, add_zsock_input);
	process_args_loop(c->w_zsock, add_zsock_output);
	process_args_loop(c->r_nmsg, add_file_input);
	process_args_loop(c->w_nmsg, add_file_output);

	for (int i = 0; i < ARGV_ARRAY_COUNT(c->r_channel); i++) {
		char *ch;
		char **alias = NULL;
		int num_aliases;

		ch = *ARGV_ARRAY_ENTRY_P(c->r_channel, char *, i);
		if (c->debug >= 2)
			fprintf(stderr, "%s: looking up channel '%s'\n", argv_program, ch);
		num_aliases = nmsg_chalias_lookup(ch, &alias);
		if (num_aliases <= 0)
			usage("channel alias lookup failed");
		for (int j = 0; j < num_aliases; j++) {
			if (strstr(alias[j], "://"))
				usage("channel alias appears to be a ZeroMQ endpoint");
			add_sock_input(c, alias[j]);
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
		if (num_aliases <= 0)
			usage("zchannel alias lookup failed");
		for (int j = 0; j < num_aliases; j++) {
			if (!strstr(alias[j], "://"))
				usage("zchannel alias needs to be a ZeroMQ endpoint");
			add_zsock_input(c, alias[j]);
		}
		nmsg_chalias_free(&alias);
	}

	/* pres inputs and outputs */
	process_args_loop_mod(c->r_pres, add_pres_input, mod);
	process_args_loop(c->w_pres, add_pres_output);

	/* json inputs and outputs */
	process_args_loop(c->r_json, add_json_input);
	process_args_loop(c->w_json, add_json_output);

	/* filter modules */
	process_args_loop(c->filters, add_filter_module);

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
			exit(EXIT_FAILURE);
		}
	}

#undef process_args_loop
#undef process_args_loop_mod

	/* validation */
	if (c->n_inputs == 0)
		usage("no data sources specified");
	if (c->n_outputs == 0) {
		/* implicit "-o -" */
		add_pres_output(c, "-");
	}

	/* daemonize if necessary */
	if (c->daemon) {
		if (!daemonize()) {
			fprintf(stderr, "nmsgtool: unable to daemonize: %s\n",
				strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/* write pidfile if necessary */
	if (c->pidfile != NULL && fp_pidfile != NULL)
		pidfile_write(fp_pidfile);
}
