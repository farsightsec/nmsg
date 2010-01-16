/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_REPLACE_INTERNAL_H
#define USTR_REPLACE_INTERNAL_H 1

#ifndef USTR_MAIN_H
# error " You should have already included ustr-main.h, or just include ustr.h"
#endif

USTR_CONF_e_PROTO
size_t ustrp__replace_inline_buf(struct Ustr_pool *, struct Ustr **,
                                 const void *, size_t,
                                 const void *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3, 5));
USTR_CONF_e_PROTO
size_t ustrp__replace_buf(struct Ustr_pool *, struct Ustr **,
                             const void *, size_t, const void *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3, 5));
USTR_CONF_e_PROTO
size_t ustrp__replace(struct Ustr_pool *, struct Ustr **,const struct Ustr *,
                         const struct Ustr *, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3, 4));
USTR_CONF_e_PROTO
size_t ustrp__replace_inline_rep_chr(struct Ustr_pool *p, struct Ustr **ps1,
                                     char, size_t, char, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
size_t ustrp__replace_rep_chr(struct Ustr_pool *p, struct Ustr **ps1,
                              char, size_t, char, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

#endif
