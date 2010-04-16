/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_SET_H
#define USTR_SET_H 1

#ifndef USTR_MAIN_H
#error " You should have already included ustr-main.h, or just include ustr.h."
#endif

#define USTR_SET_OBJ(x, y)  ustr_set_buf(x, y, sizeof(y))
#define USTR_SET_OSTR(x, y) ustr_set_buf(x, y, sizeof(y) - 1)

#define USTRP_SET_OBJ(p, x, y)  ustrp_set_buf(p, x, y, sizeof(y))
#define USTRP_SET_OSTR(p, x, y) ustrp_set_buf(p, x, y, sizeof(y) - 1)

USTR_CONF_E_PROTO int ustr_set_undef(struct Ustr **, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_set_empty(struct Ustr **)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_set_buf(struct Ustr **, const void *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_set_cstr(struct Ustr **, const char *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_set(struct Ustr **, const struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
int ustr_set_subustr(struct Ustr **, const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_set_rep_chr(struct Ustr **, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
int ustrp_set_undef(struct Ustr_pool *, struct Ustrp **, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO int ustrp_set_empty(struct Ustr_pool *, struct Ustrp **)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO
int ustrp_set_buf(struct Ustr_pool *, struct Ustrp **,const void *,size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_EI_PROTO
int ustrp_set_cstr(struct Ustr_pool *, struct Ustrp **, const char *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_set(struct Ustr_pool *, struct Ustrp **, const struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_set_subustrp(struct Ustr_pool *, struct Ustrp **,
                       const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3));
USTR_CONF_E_PROTO
int ustrp_set_rep_chr(struct Ustr_pool *, struct Ustrp **, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

#ifdef USTR_FMT_H
# if USTR_CONF_HAVE_VA_COPY
USTR_CONF_E_PROTO
int ustr_set_vfmt_lim(struct Ustr **, size_t, const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((1, 3)) USTR__COMPILE_ATTR_FMT(3, 0);
USTR_CONF_E_PROTO int ustr_set_vfmt(struct Ustr **, const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((1, 2)) USTR__COMPILE_ATTR_FMT(2, 0);

USTR_CONF_E_PROTO
int ustrp_set_vfmt_lim(struct Ustr_pool *, struct Ustrp **, size_t,
                       const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 0);
USTR_CONF_E_PROTO
int ustrp_set_vfmt(struct Ustr_pool *, struct Ustrp **, const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3)) USTR__COMPILE_ATTR_FMT(3, 0);
# endif

USTR_CONF_E_PROTO int ustr_set_fmt_lim(struct Ustr **, size_t,const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((1, 3)) USTR__COMPILE_ATTR_FMT(3, 4);
USTR_CONF_E_PROTO int ustr_set_fmt(struct Ustr **, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((1, 2)) USTR__COMPILE_ATTR_FMT(2, 3);

USTR_CONF_E_PROTO
int ustrp_set_fmt_lim(struct Ustr_pool *, struct Ustrp **, size_t,
                      const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 5);
USTR_CONF_E_PROTO
int ustrp_set_fmt(struct Ustr_pool *, struct Ustrp **, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3)) USTR__COMPILE_ATTR_FMT(3, 4);
#endif

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-set-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-set-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO int ustr_set_cstr(struct Ustr **ps1, const char *cstr)
{ return (ustr_set_buf(ps1, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
int ustrp_set_cstr(struct Ustr_pool *p, struct Ustrp **ps1, const char *cstr)
{ return (ustrp_set_buf(p, ps1, cstr, strlen(cstr))); }
#endif

#endif
