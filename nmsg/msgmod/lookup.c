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

/* Import. */

#include <strings.h>

#include "nmsg.h"
#include "private.h"

/* Export. */

nmsg_msgmod_t
nmsg_msgmod_lookup(unsigned vid, unsigned msgtype) {
	struct nmsg_msgmodset *ms = _nmsg_global_msgmodset;
	struct nmsg_msgmod *mod;
	struct nmsg_msgvendor *msgv;

	if (vid <= ms->nv) {
		msgv = ms->vendors[vid];
		if (msgv != NULL && msgtype <= msgv->nm) {
			mod = msgv->msgtypes[msgtype];
			return (mod);
		}
	}

	return (NULL);
}

nmsg_msgmod_t
nmsg_msgmod_lookup_byname(const char *vname, const char *mname) {
	unsigned vid = 0;
	unsigned msgtype = 0;

	vid = nmsg_msgmod_vname_to_vid(vname);
	msgtype = nmsg_msgmod_mname_to_msgtype(vid, mname);

	if (vid == 0 || msgtype == 0)
		return (NULL);

	return (nmsg_msgmod_lookup(vid, msgtype));
}

unsigned
nmsg_msgmod_vname_to_vid(const char *vname) {
	struct nmsg_msgmodset *ms = _nmsg_global_msgmodset;
	unsigned i, j;

	for (i = 0; i <= ms->nv; i++) {
		struct nmsg_msgvendor *msgv;
		msgv = ms->vendors[i];

		if (msgv != NULL) {
			for (j = 0; j <= msgv->nm; j++) {
				struct nmsg_msgmod *mod;
				mod = msgv->msgtypes[j];

				if (mod != NULL &&
				    strcasecmp(mod->plugin->vendor.name, vname) == 0)
					return (mod->plugin->vendor.id);
			}
		}
	}
	return (0);
}

unsigned
nmsg_msgmod_mname_to_msgtype(unsigned vid, const char *mname) {
	struct nmsg_msgmodset *ms = _nmsg_global_msgmodset;
	unsigned i;

	if (vid <= ms->nv) {
		struct nmsg_msgvendor *msgv;

		msgv = ms->vendors[vid];
		if (msgv == NULL)
			return (0);
		for (i = 0; i <= msgv->nm; i++) {
			struct nmsg_msgmod *mod;

			mod = msgv->msgtypes[i];
			if (mod != NULL) {
				if (strcasecmp(mod->plugin->msgtype.name, mname) == 0)
					return (mod->plugin->msgtype.id);
			}
		}
	}

	return (0);
}

const char *
nmsg_msgmod_vid_to_vname(unsigned vid) {
	struct nmsg_msgmodset *ms = _nmsg_global_msgmodset;
	struct nmsg_msgvendor *msgv;
	unsigned i;

	if (vid > ms->nv)
		return (NULL);
	msgv = ms->vendors[vid];
	if (msgv == NULL)
		return (NULL);
	for (i = 0; i <= msgv->nm; i++) {
		struct nmsg_msgmod *mod;

		mod = msgv->msgtypes[i];
		if (mod != NULL && mod->plugin->vendor.id == vid)
			return (mod->plugin->vendor.name);
	}
	return (NULL);
}

const char *
nmsg_msgmod_msgtype_to_mname(unsigned vid, unsigned msgtype) {
	struct nmsg_msgmodset *ms = _nmsg_global_msgmodset;
	struct nmsg_msgvendor *msgv;
	unsigned i;

	if (vid > ms->nv)
		return (NULL);
	msgv = ms->vendors[vid];
	if (msgv == NULL)
		return (NULL);
	for (i = 0; i <= msgv->nm; i++) {
		struct nmsg_msgmod *mod;

		mod = msgv->msgtypes[i];
		if (mod != NULL && mod->plugin->vendor.id == vid) {
			if (mod->plugin->msgtype.id == msgtype)
				return (mod->plugin->msgtype.name);
		}
	}
	return (NULL);
}

unsigned
nmsg_msgmod_get_max_vid(void) {
	struct nmsg_msgmodset *ms = _nmsg_global_msgmodset;

	return (ms->nv);
}

unsigned
nmsg_msgmod_get_max_msgtype(unsigned vid) {
	struct nmsg_msgmodset *ms = _nmsg_global_msgmodset;
	struct nmsg_msgvendor *msgv;

	if (vid > ms->nv)
		return (0);
	msgv = ms->vendors[vid];
	if (msgv == NULL)
		return (0);
	return (msgv->nm);
}
