#ifndef NMSGTOOL_BUF_H
#define NMSGTOOL_BUF_H

#include "config.h"
#include "nmsgtool.h"

extern void nmsgtool_add_sock_input(nmsgtool_ctx *, const char *ss);
extern void nmsgtool_add_file_input(nmsgtool_ctx *, const char *fn);
extern void nmsgtool_add_pres_input(nmsgtool_ctx *, nmsg_pbmod, const char *fn);

extern void nmsgtool_add_sock_output(nmsgtool_ctx *, const char *ss);
extern void nmsgtool_add_file_output(nmsgtool_ctx *, const char *fn);
extern void nmsgtool_add_pres_output(nmsgtool_ctx *, nmsg_pbmod, const char *fn);

#endif
