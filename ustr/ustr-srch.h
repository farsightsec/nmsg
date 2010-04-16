/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_SRCH_H
#define USTR_SRCH_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

USTR_CONF_E_PROTO size_t ustr_srch_chr_fwd(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO size_t ustr_srch_chr_rev(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_srch_buf_fwd(const struct Ustr *, size_t, const void *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_srch_buf_rev(const struct Ustr *, size_t, const void *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustr_srch_fwd(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_srch_rev(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustr_srch_cstr_fwd(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_srch_cstr_rev(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_srch_subustr_fwd(const struct Ustr *, size_t,
                             const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_srch_subustr_rev(const struct Ustr *, size_t,
                             const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_srch_rep_chr_fwd(const struct Ustr *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_srch_rep_chr_rev(const struct Ustr *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

/* ignore case */
USTR_CONF_E_PROTO
size_t ustr_srch_case_chr_fwd(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_srch_case_chr_rev(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_srch_case_buf_fwd(const struct Ustr *, size_t, const void *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_srch_case_buf_rev(const struct Ustr *, size_t, const void *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustr_srch_case_fwd(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_srch_case_rev(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustr_srch_case_cstr_fwd(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_srch_case_cstr_rev(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_srch_case_subustr_fwd(const struct Ustr *, size_t,
                                  const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_srch_case_subustr_rev(const struct Ustr *, size_t,
                                  const struct Ustr *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_srch_case_rep_chr_fwd(const struct Ustr *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_srch_case_rep_chr_rev(const struct Ustr *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-srch-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-srch-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
size_t ustr_srch_fwd(const struct Ustr *s1, size_t off, const struct Ustr *s2)
{ return (ustr_srch_buf_fwd(s1, off, ustr_cstr(s2), ustr_len(s2))); }
USTR_CONF_II_PROTO
size_t ustr_srch_rev(const struct Ustr *s1, size_t off, const struct Ustr *s2)
{ return (ustr_srch_buf_rev(s1, off, ustr_cstr(s2), ustr_len(s2))); }

USTR_CONF_II_PROTO
size_t ustr_srch_cstr_fwd(const struct Ustr *s1, size_t off, const char *cstr)
{ return (ustr_srch_buf_fwd(s1, off, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustr_srch_cstr_rev(const struct Ustr *s1, size_t off, const char *cstr)
{ return (ustr_srch_buf_rev(s1, off, cstr, strlen(cstr))); }

/* ignore case */
USTR_CONF_II_PROTO
size_t ustr_srch_case_fwd(const struct Ustr *s1,size_t o, const struct Ustr *s2)
{ return (ustr_srch_case_buf_fwd(s1, o, ustr_cstr(s2), ustr_len(s2))); }
USTR_CONF_II_PROTO
size_t ustr_srch_case_rev(const struct Ustr *s1,size_t o, const struct Ustr *s2)
{ return (ustr_srch_case_buf_rev(s1, o, ustr_cstr(s2), ustr_len(s2))); }

USTR_CONF_II_PROTO
size_t ustr_srch_case_cstr_fwd(const struct Ustr *s1,size_t o, const char *cstr)
{ return (ustr_srch_case_buf_fwd(s1, o, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustr_srch_case_cstr_rev(const struct Ustr *s1,size_t o, const char *cstr)
{ return (ustr_srch_case_buf_rev(s1, o, cstr, strlen(cstr))); }
#endif

/* ---------------- pool wrapper APIs ---------------- */

USTR_CONF_EI_PROTO size_t ustrp_srch_chr_fwd(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO size_t ustrp_srch_chr_rev(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_buf_fwd(const struct Ustrp *, size_t, const void *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_buf_rev(const struct Ustrp *, size_t, const void *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_fwd(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_rev(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_cstr_fwd(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_cstr_rev(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_subustrp_fwd(const struct Ustrp *, size_t,
                               const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_subustrp_rev(const struct Ustrp *, size_t,
                               const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_rep_chr_fwd(const struct Ustrp *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_rep_chr_rev(const struct Ustrp *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

/* ignore case */
USTR_CONF_EI_PROTO
size_t ustrp_srch_case_chr_fwd(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_case_chr_rev(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_case_buf_fwd(const struct Ustrp *,size_t, const void *,size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_case_buf_rev(const struct Ustrp *,size_t, const void *,size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_case_fwd(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_case_rev(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_case_cstr_fwd(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_case_cstr_rev(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_case_subustrp_fwd(const struct Ustrp *, size_t,
                               const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_case_subustrp_rev(const struct Ustrp *, size_t,
                               const struct Ustrp *, size_t, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO
size_t ustrp_srch_case_rep_chr_fwd(const struct Ustrp *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_srch_case_rep_chr_rev(const struct Ustrp *, size_t, char, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();


#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
size_t ustrp_srch_chr_fwd(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_srch_chr_fwd(&s1->s, off, chr)); }
USTR_CONF_II_PROTO
size_t ustrp_srch_chr_rev(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_srch_chr_rev(&s1->s, off, chr)); }

USTR_CONF_II_PROTO size_t ustrp_srch_buf_fwd(const struct Ustrp *s1, size_t off,
                                             const void *buf, size_t len)
{ return (ustr_srch_buf_fwd(&s1->s, off, buf, len)); }
USTR_CONF_II_PROTO size_t ustrp_srch_buf_rev(const struct Ustrp *s1, size_t off,
                                             const void *buf, size_t len)
{ return (ustr_srch_buf_rev(&s1->s, off, buf, len)); }

USTR_CONF_II_PROTO size_t ustrp_srch_fwd(const struct Ustrp *s1, size_t off,
                                         const struct Ustrp *s2)
{ return (ustr_srch_fwd(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO size_t ustrp_srch_rev(const struct Ustrp *s1, size_t off,
                                         const struct Ustrp *s2)
{ return (ustr_srch_rev(&s1->s, off, &s2->s)); }

USTR_CONF_II_PROTO
size_t ustrp_srch_cstr_fwd(const struct Ustrp *s1, size_t off, const char *cstr)
{ return (ustrp_srch_buf_fwd(s1, off, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustrp_srch_cstr_rev(const struct Ustrp *s1, size_t off, const char *cstr)
{ return (ustrp_srch_buf_rev(s1, off, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
size_t ustrp_srch_subustrp_fwd(const struct Ustrp *s1, size_t off,
                               const struct Ustrp *s2, size_t pos, size_t len)
{ return (ustr_srch_subustr_fwd(&s1->s, off, &s2->s, pos, len)); }
USTR_CONF_II_PROTO
size_t ustrp_srch_subustrp_rev(const struct Ustrp *s1, size_t off,
                               const struct Ustrp *s2, size_t pos, size_t len)
{ return (ustr_srch_subustr_rev(&s1->s, off, &s2->s, pos, len)); }

USTR_CONF_II_PROTO
size_t ustrp_srch_rep_chr_fwd(const struct Ustrp *s1, size_t off,
                              char data, size_t len)
{ return (ustr_srch_rep_chr_fwd(&s1->s, off, data, len)); }
USTR_CONF_II_PROTO
size_t ustrp_srch_rep_chr_rev(const struct Ustrp *s1, size_t off,
                              char data, size_t len)
{ return (ustr_srch_rep_chr_rev(&s1->s, off, data, len)); }

/* ignore case */
USTR_CONF_II_PROTO
size_t ustrp_srch_case_chr_fwd(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_srch_case_chr_fwd(&s1->s, off, chr)); }
USTR_CONF_II_PROTO
size_t ustrp_srch_case_chr_rev(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_srch_case_chr_rev(&s1->s, off, chr)); }

USTR_CONF_II_PROTO
size_t ustrp_srch_case_buf_fwd(const struct Ustrp *s1, size_t off,
                               const void *buf, size_t len)
{ return (ustr_srch_case_buf_fwd(&s1->s, off, buf, len)); }
USTR_CONF_II_PROTO
size_t ustrp_srch_case_buf_rev(const struct Ustrp *s1, size_t off,
                               const void *buf, size_t len)
{ return (ustr_srch_case_buf_rev(&s1->s, off, buf, len)); }

USTR_CONF_II_PROTO size_t ustrp_srch_case_fwd(const struct Ustrp *s1,size_t off,
                                              const struct Ustrp *s2)
{ return (ustr_srch_case_fwd(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO size_t ustrp_srch_case_rev(const struct Ustrp *s1,size_t off,
                                              const struct Ustrp *s2)
{ return (ustr_srch_case_rev(&s1->s, off, &s2->s)); }

USTR_CONF_II_PROTO
size_t ustrp_srch_case_cstr_fwd(const struct Ustrp *s1, size_t off,
                                const char *cstr)
{ return (ustrp_srch_case_buf_fwd(s1, off, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustrp_srch_case_cstr_rev(const struct Ustrp *s1, size_t off,
                                const char *cstr)
{ return (ustrp_srch_case_buf_rev(s1, off, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
size_t ustrp_srch_case_subustrp_fwd(const struct Ustrp *s1, size_t off,
                                    const struct Ustrp *s2,
                                    size_t pos, size_t len)
{ return (ustr_srch_case_subustr_fwd(&s1->s, off, &s2->s, pos, len)); }
USTR_CONF_II_PROTO
size_t ustrp_srch_case_subustrp_rev(const struct Ustrp *s1, size_t off,
                                    const struct Ustrp *s2,
                                    size_t pos, size_t len)
{ return (ustr_srch_case_subustr_rev(&s1->s, off, &s2->s, pos, len)); }

USTR_CONF_II_PROTO
size_t ustrp_srch_case_rep_chr_fwd(const struct Ustrp *s1, size_t off,
                                   char data, size_t len)
{ return (ustr_srch_case_rep_chr_fwd(&s1->s, off, data, len)); }
USTR_CONF_II_PROTO
size_t ustrp_srch_case_rep_chr_rev(const struct Ustrp *s1, size_t off,
                                   char data, size_t len)
{ return (ustr_srch_case_rep_chr_rev(&s1->s, off, data, len)); }

#endif

#endif
