/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_FMT_H
#define USTR_FMT_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

#if USTR_CONF_HAVE_VA_COPY
USTR_CONF_E_PROTO
int ustr_add_vfmt_lim(struct Ustr **, size_t, const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((1, 3)) USTR__COMPILE_ATTR_FMT(3, 0);
USTR_CONF_E_PROTO int ustr_add_vfmt(struct Ustr **, const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((1, 2)) USTR__COMPILE_ATTR_FMT(2, 0);
USTR_CONF_E_PROTO struct Ustr *ustr_dupx_vfmt_lim(size_t, size_t, int, int,
                                                  size_t, const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((6)) USTR__COMPILE_ATTR_FMT(6, 0);
USTR_CONF_E_PROTO struct Ustr *ustr_dup_vfmt_lim(size_t, const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((2)) USTR__COMPILE_ATTR_FMT(2, 0);
USTR_CONF_E_PROTO
struct Ustr *ustr_dupx_vfmt(size_t, size_t, int, int, const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((5)) USTR__COMPILE_ATTR_FMT(5, 0);
USTR_CONF_E_PROTO struct Ustr *ustr_dup_vfmt(const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((1)) USTR__COMPILE_ATTR_FMT(1, 0);

USTR_CONF_E_PROTO
int ustrp_add_vfmt_lim(struct Ustr_pool *, struct Ustrp **, size_t,
                       const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 0);
USTR_CONF_E_PROTO int ustrp_add_vfmt(struct Ustr_pool *, struct Ustrp **,
                                     const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3)) USTR__COMPILE_ATTR_FMT(3, 0);
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_vfmt_lim(struct Ustr_pool *, size_t, size_t, int, int,
                                  size_t, const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((7)) USTR__COMPILE_ATTR_FMT(7, 0);
USTR_CONF_E_PROTO struct Ustrp *ustrp_dup_vfmt_lim(struct Ustr_pool *, size_t,
                                                   const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((3)) USTR__COMPILE_ATTR_FMT(3, 0);
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_vfmt(struct Ustr_pool *, size_t, size_t, int,
                              int, const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((6)) USTR__COMPILE_ATTR_FMT(6, 0);
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dup_vfmt(struct Ustr_pool *, const char *, va_list)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_L((2)) USTR__COMPILE_ATTR_FMT(2, 0);

/* even without va_copy, we can still do *_fmt using lots of copy and paste */
USTR_CONF_E_PROTO int ustr_add_fmt(struct Ustr **, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((1, 2)) USTR__COMPILE_ATTR_FMT(2, 3);
USTR_CONF_E_PROTO int ustr_add_fmt_lim(struct Ustr **, size_t,const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((1, 3)) USTR__COMPILE_ATTR_FMT(3, 4);
USTR_CONF_E_PROTO struct Ustr *ustr_dupx_fmt_lim(size_t, size_t, int, int,
                                                 size_t, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((6)) USTR__COMPILE_ATTR_FMT(6, 7);
USTR_CONF_E_PROTO struct Ustr *ustr_dup_fmt_lim(size_t, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2)) USTR__COMPILE_ATTR_FMT(2, 3);
USTR_CONF_E_PROTO
struct Ustr *ustr_dupx_fmt(size_t, size_t, int, int, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((5)) USTR__COMPILE_ATTR_FMT(5, 6);
USTR_CONF_E_PROTO struct Ustr *ustr_dup_fmt(const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((1)) USTR__COMPILE_ATTR_FMT(1, 2);

USTR_CONF_E_PROTO
int ustrp_add_fmt(struct Ustr_pool *, struct Ustrp **, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3)) USTR__COMPILE_ATTR_FMT(3, 4);
USTR_CONF_E_PROTO
int ustrp_add_fmt_lim(struct Ustr_pool *, struct Ustrp **, size_t,
                      const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 5);
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_fmt_lim(struct Ustr_pool *, size_t, size_t, int,
                                 int, size_t, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((7)) USTR__COMPILE_ATTR_FMT(7, 8);
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dup_fmt_lim(struct Ustr_pool *, size_t, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((3)) USTR__COMPILE_ATTR_FMT(3, 4);
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dupx_fmt(struct Ustr_pool *, size_t, size_t, int, int,
                             const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((6)) USTR__COMPILE_ATTR_FMT(6, 7);
USTR_CONF_E_PROTO
struct Ustrp *ustrp_dup_fmt(struct Ustr_pool *, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2)) USTR__COMPILE_ATTR_FMT(2, 3);
#endif

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-fmt-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-fmt-code.h"
#endif

#endif
