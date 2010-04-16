/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_INS_INTERNAL_H
#define USTR_INS_INTERNAL_H 1

#ifndef USTR_MAIN_H
# error " You should have already included ustr-main.h, or just include ustr.h"
#endif

USTR_CONF_e_PROTO
int ustrp__ins_undef(struct Ustr_pool *, struct Ustr **ps1, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_e_PROTO
int ustrp__ins_buf(struct Ustr_pool *,struct Ustr **,size_t,const void *,size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4));
USTR_CONF_e_PROTO
int ustrp__ins(struct Ustr_pool *, struct Ustr **, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4));
USTR_CONF_e_PROTO
int ustrp__ins_subustr(struct Ustr_pool *, struct Ustr **, size_t,
                       const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4));
USTR_CONF_E_PROTO
int ustrp__ins_rep_chr(struct Ustr_pool *, struct Ustr **, size_t, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

#ifdef USTR_FMT_H
# if USTR_CONF_HAVE_VA_COPY
USTR_CONF_e_PROTO
int ustrp__ins_vfmt_lim(struct Ustr_pool *, struct Ustr **, size_t, size_t,
                        const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 5)) USTR__COMPILE_ATTR_FMT(5, 0);
# endif
#endif

#endif
