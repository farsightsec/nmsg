/* nmsgtool.c - libnmsg tool shell */

/*
 * Copyright (c) 2008 by Internet Systems Consortium, Inc. ("ISC")
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

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>

#include <nmsg.h>
#include "config.h"

#include "argv.h"

static unsigned nmsg_vid;
static char *nmsg_vendor = NULL;
static unsigned nmsg_msgtype;

static argv_t args[] = {
	{ 'V', "vendor", ARGV_CHAR_P, &nmsg_vendor, "vname", "vendor" },
	{ 'T', "msgtype", ARGV_U_INT, &nmsg_msgtype, "msgtype", "message type" },
	{ ARGV_LAST, 0, 0, 0, 0, 0 }
};

int main(int argc, char **argv) {
	nmsg_pbmodset pms;

	argv_process(args, argc, argv);
	pms = nmsg_pbmodset_load(NMSG_LIBDIR);

	if (nmsg_vendor) {
		nmsg_vid = nmsg_pbmodset_vname_to_vid(pms, nmsg_vendor);
		printf("vendor=%s vid=%u msgtype=%u\n", nmsg_vendor, nmsg_vid, nmsg_msgtype);
	}
	if (pms != NULL) {
		nmsg_pbmodset_destroy(&pms);
	}
	return (0);
}
