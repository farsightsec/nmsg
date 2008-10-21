#ifndef NMSGTOOL_BUF_H
#define NMSGTOOL_BUF_H

#include "config.h"
#include "nmsgtool.h"

extern void nmsgtool_inputs_add_sock(nmsgtool_ctx *, const char *ss);
extern void nmsgtool_inputs_add_file(nmsgtool_ctx *, const char *fn);
extern void nmsgtool_inputs_destroy(nmsgtool_ctx *);

extern void nmsgtool_outputs_add_sock(nmsgtool_ctx *, const char *ss);
extern void nmsgtool_outputs_add_file(nmsgtool_ctx *, const char *fn);
extern void nmsgtool_outputs_destroy(nmsgtool_ctx *);

#endif
