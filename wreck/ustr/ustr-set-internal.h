/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_SET_INTERNAL_H
#define USTR_SET_INTERNAL_H 1

#ifndef USTR_SET_H
# error " You should have already included ustr-set.h, or just include ustr.h"
#endif

USTR_CONF_e_PROTO
int ustrp__set_undef(struct Ustr_pool *, struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO int ustrp__set_empty(struct Ustr_pool *, struct Ustr **)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
int ustrp__set_buf(struct Ustr_pool *, struct Ustr **, const void *, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO
int ustrp__set(struct Ustr_pool *, struct Ustr **, const struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO int ustrp__set_subustr(struct Ustr_pool *, struct Ustr **,
                                         const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_e_PROTO
int ustrp__set_rep_chr(struct Ustr_pool *, struct Ustr **, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

#ifdef USTR_FMT_H
# if USTR_CONF_HAVE_VA_COPY
USTR_CONF_e_PROTO
int ustrp__set_vfmt_lim(struct Ustr_pool *, struct Ustr **, size_t,
                        const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 0);
# endif
#endif


#endif
