/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_IO_INTERNAL_H
#define USTR_IO_INTERNAL_H 1

#ifndef USTR_IO_H
# error " You should have already included ustr-io.h, or just include ustr.h"
#endif

USTR_CONF_e_PROTO
int ustrp__io_get(struct Ustr_pool *, struct Ustr **, FILE *, size_t, size_t *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO int ustrp__io_getfile(struct Ustr_pool *, struct Ustr**,FILE*)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO int ustrp__io_getfilename(struct Ustr_pool *,struct Ustr **,
                                            const char *)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));

USTR_CONF_e_PROTO
int ustrp__io_getdelim(struct Ustr_pool *, struct Ustr **, FILE *, char)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));

USTR_CONF_e_PROTO
int ustrp__io_put(struct Ustr_pool *, struct Ustr **, FILE *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO
int ustrp__io_putline(struct Ustr_pool *, struct Ustr **, FILE *, size_t)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO
int ustrp__io_putfilename(struct Ustr_pool *, struct Ustr **,
                          const char *, const char *)
   USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3, 4));

#endif
