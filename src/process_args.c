/*
 * Copyright (c) 2008-2013 by Internet Systems Consortium, Inc. ("ISC")
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
		if (fd != -1)
			fchown(fd, pw->pw_uid, pw->pw_gid);
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
#ifdef HAVE_LIBXS
		fprintf(stderr, "%s: version %s\n", argv_program, PACKAGE_VERSION);
#else /* HAVE_LIBXS */
		fprintf(stderr, "%s: version %s (without libxs support)\n",
			argv_program, PACKAGE_VERSION);
#endif /* HAVE_LIBXS */
		exit(EXIT_SUCCESS);
	}

	if (c->endline == NULL)
		c->endline_str = strdup("\n");
	else
		c->endline_str = unescape(c->endline);

	if (c->mtu == 0)
		c->mtu = NMSG_WBUFSZ_JUMBO;
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
	if (c->debug > 0)
		nmsg_io_set_debug(c->io, c->debug);
	if (c->count > 0)
		nmsg_io_set_count(c->io, c->count);
	if (c->interval > 0)
		nmsg_io_set_interval(c->io, c->interval);
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

	/* XS context */
	if (ARGV_ARRAY_COUNT(c->r_xsock) > 0 ||
	    ARGV_ARRAY_COUNT(c->w_xsock) > 0 ||
	    ARGV_ARRAY_COUNT(c->r_xchannel) > 0)
	{
#ifdef HAVE_LIBXS
		c->xs_ctx = xs_init();
		if (c->xs_ctx == NULL) {
			fprintf(stderr, "%s: xs_init() failed: %s\n",
				argv_program, strerror(errno));
			exit(EXIT_FAILURE);
		}
#else /* HAVE_LIBXS */
		fprintf(stderr, "%s: Error: compiled without libxs support\n",
			argv_program);
		exit(EXIT_FAILURE);
#endif /* HAVE_LIBXS */
	}

	/* nmsg inputs and outputs */
	process_args_loop(c->r_sock, add_sock_input);
	process_args_loop(c->w_sock, add_sock_output);
	process_args_loop(c->r_xsock, add_xsock_input);
	process_args_loop(c->w_xsock, add_xsock_output);
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
				usage("channel alias appears to be an xchannel");
			add_sock_input(c, alias[j]);
		}
		nmsg_chalias_free(&alias);
	}

	for (int i = 0; i < ARGV_ARRAY_COUNT(c->r_xchannel); i++) {
		char *ch;
		char **alias = NULL;
		int num_aliases;

		ch = *ARGV_ARRAY_ENTRY_P(c->r_xchannel, char *, i);
		if (c->debug >= 2)
			fprintf(stderr, "%s: looking up xchannel '%s'\n", argv_program, ch);
		num_aliases = nmsg_chalias_lookup(ch, &alias);
		if (num_aliases <= 0)
			usage("xchannel alias lookup failed");
		for (int j = 0; j < num_aliases; j++)
			add_xsock_input(c, alias[j]);
		nmsg_chalias_free(&alias);
	}

	/* pres inputs and outputs */
	process_args_loop_mod(c->r_pres, add_pres_input, mod);
	process_args_loop(c->w_pres, add_pres_output);

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
