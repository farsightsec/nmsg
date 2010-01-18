/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_INS_H
#define USTR_INS_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

#define USTR_INS_OBJ(x, y, z)  ustr_ins_buf(x, y, z, sizeof(z))
#define USTR_INS_OSTR(x, y, z) ustr_ins_buf(x, y, z, sizeof(z) - 1)

#define USTRP_INS_OBJ(p, x, y, z)  ustrp_ins_buf(p, x, y, z, sizeof(z))
#define USTRP_INS_OSTR(p, x, y, z) ustrp_ins_buf(p, x, y, z, sizeof(z) - 1)


USTR_CONF_E_PROTO int ustr_ins_undef(struct Ustr **, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_ins_buf(struct Ustr **, size_t, const void *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_ins(struct Ustr **, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO int ustr_ins_cstr(struct Ustr **, size_t, const char *)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
int ustr_ins_subustr(struct Ustr **, size_t, const struct Ustr *, size_t,size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO int ustr_ins_rep_chr(struct Ustr **, size_t, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
int ustrp_ins_undef(struct Ustr_pool *, struct Ustrp **, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));
USTR_CONF_E_PROTO int ustrp_ins_buf(struct Ustr_pool *, struct Ustrp **, size_t,
                                    const void *, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4));
USTR_CONF_E_PROTO
int ustrp_ins(struct Ustr_pool *, struct Ustrp **, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4));
USTR_CONF_EI_PROTO
int ustrp_ins_cstr(struct Ustr_pool *, struct Ustrp **, size_t, const char *)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4));
USTR_CONF_E_PROTO
int ustrp_ins_subustrp(struct Ustr_pool *, struct Ustrp **, size_t,
                       const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4));
USTR_CONF_E_PROTO
int ustrp_ins_rep_chr(struct Ustr_pool *, struct Ustrp **, size_t, char, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2));

#ifdef USTR_FMT_H
# if USTR_CONF_HAVE_VA_COPY
USTR_CONF_E_PROTO
int ustr_ins_vfmt_lim(struct Ustr **, size_t, size_t, const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((1, 4)) USTR__COMPILE_ATTR_FMT(4, 0);
USTR_CONF_E_PROTO
int ustr_ins_vfmt(struct Ustr **, size_t, const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((1, 3)) USTR__COMPILE_ATTR_FMT(3, 0);

USTR_CONF_E_PROTO
int ustrp_ins_vfmt_lim(struct Ustr_pool *, struct Ustrp **, size_t, size_t,
                       const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 5)) USTR__COMPILE_ATTR_FMT(5, 0);
USTR_CONF_E_PROTO int ustrp_ins_vfmt(struct Ustr_pool *, struct Ustrp **,size_t,
                                     const char *, va_list)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 0);
USTR_CONF_E_PROTO
int ustr_ins_fmt_lim(struct Ustr **, size_t, size_t, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((1, 4)) USTR__COMPILE_ATTR_FMT(4, 5);
USTR_CONF_E_PROTO int ustr_ins_fmt(struct Ustr **, size_t, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((1, 3)) USTR__COMPILE_ATTR_FMT(3, 4);

USTR_CONF_E_PROTO
int ustrp_ins_fmt_lim(struct Ustr_pool *, struct Ustrp **, size_t, size_t,
                      const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2, 5)) USTR__COMPILE_ATTR_FMT(5, 6);
USTR_CONF_E_PROTO
int ustrp_ins_fmt(struct Ustr_pool *, struct Ustrp **,size_t, const char *, ...)
    USTR__COMPILE_ATTR_NONNULL_L((2, 4)) USTR__COMPILE_ATTR_FMT(4, 5);
# endif
#endif

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-ins-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-ins-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO int ustr_ins_cstr(struct Ustr **s1, size_t p, const char *c) 
{ return (ustr_ins_buf(s1, p, c, strlen(c))); }
USTR_CONF_II_PROTO int
ustrp_ins_cstr(struct Ustr_pool *x, struct Ustrp **s1, size_t p, const char *c)
{ return (ustrp_ins_buf(x, s1, p, c, strlen(c))); }
#endif


#endif
