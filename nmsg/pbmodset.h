#ifndef NMSG_PBMODSET_H
#define NMSG_PBMODSET_H

#include <nmsg.h>

nmsg_pbmodset
nmsg_pbmodset_open(const char *path, int debug);

void
nmsg_pbmodset_destroy(nmsg_pbmodset *);

nmsg_pbmod
nmsg_pbmodset_lookup(nmsg_pbmodset, unsigned vid, unsigned msgtype);

unsigned
nmsg_pbmodset_mname2msgtype(nmsg_pbmodset, unsigned vid, const char *mname);

const char *
nmsg_pbmodset_msgtype2mname(nmsg_pbmodset ms, unsigned vid, unsigned msgtype);

const char *
nmsg_pbmodset_vid2vname(nmsg_pbmodset ms, unsigned vid);

unsigned
nmsg_pbmodset_vname2vid(nmsg_pbmodset, const char *);

#endif
