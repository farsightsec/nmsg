/* Copyright (c) 2007 James Antill -- See LICENSE file for terms. */
#ifndef USTR_SPN_H
#define USTR_SPN_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

/* normal strspn() like, deals with embeded NILs */
USTR_CONF_E_PROTO size_t ustr_spn_chr_fwd(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO size_t ustr_spn_chr_rev(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_spn_chrs_fwd(const struct Ustr *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_spn_chrs_rev(const struct Ustr *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_spn_fwd(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_spn_rev(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_spn_cstr_fwd(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_spn_cstr_rev(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO size_t ustr_cspn_chr_fwd(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO size_t ustr_cspn_chr_rev(const struct Ustr *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_cspn_chrs_fwd(const struct Ustr *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_cspn_chrs_rev(const struct Ustr *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_cspn_fwd(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_cspn_rev(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_cspn_cstr_fwd(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_cspn_cstr_rev(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

#ifdef USTR_UTF8_H
USTR_CONF_E_PROTO
size_t ustr_utf8_spn_chrs_fwd(const struct Ustr *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_utf8_spn_chrs_rev(const struct Ustr *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_spn_fwd(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_spn_rev(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_spn_cstr_fwd(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_spn_cstr_rev(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_E_PROTO
size_t ustr_utf8_cspn_chrs_fwd(const struct Ustr *,size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_utf8_cspn_chrs_rev(const struct Ustr *,size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_cspn_fwd(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_cspn_rev(const struct Ustr *, size_t, const struct Ustr *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_cspn_cstr_fwd(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_utf8_cspn_cstr_rev(const struct Ustr *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-spn-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
size_t ustr_spn_cstr_fwd(const struct Ustr *s1, size_t off, const char *cstr)
{ return (ustr_spn_chrs_fwd(s1, off, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustr_spn_cstr_rev(const struct Ustr *s1, size_t off, const char *cstr)
{ return (ustr_spn_chrs_rev(s1, off, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
size_t ustr_cspn_cstr_fwd(const struct Ustr *s1, size_t off, const char *cstr)
{ return (ustr_cspn_chrs_fwd(s1, off, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustr_cspn_cstr_rev(const struct Ustr *s1, size_t off, const char *cstr)
{ return (ustr_cspn_chrs_rev(s1, off, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
size_t ustr_spn_fwd(const struct Ustr *s1, size_t off, const struct Ustr *s2)
{ return (ustr_spn_chrs_fwd(s1, off, ustr_cstr(s2), ustr_len(s2))); }
USTR_CONF_II_PROTO
size_t ustr_spn_rev(const struct Ustr *s1, size_t off, const struct Ustr *s2)
{ return (ustr_spn_chrs_rev(s1, off, ustr_cstr(s2), ustr_len(s2))); }

USTR_CONF_II_PROTO
size_t ustr_cspn_fwd(const struct Ustr *s1, size_t off, const struct Ustr *s2)
{ return (ustr_cspn_chrs_fwd(s1, off, ustr_cstr(s2), ustr_len(s2))); }
USTR_CONF_II_PROTO
size_t ustr_cspn_rev(const struct Ustr *s1, size_t off, const struct Ustr *s2)
{ return (ustr_cspn_chrs_rev(s1, off, ustr_cstr(s2), ustr_len(s2))); }

# ifdef USTR_UTF8_H
USTR_CONF_II_PROTO
size_t ustr_utf8_spn_cstr_fwd(const struct Ustr *s1,size_t off,const char *cstr)
{ return (ustr_utf8_spn_chrs_fwd(s1, off, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustr_utf8_spn_cstr_rev(const struct Ustr *s1,size_t off,const char *cstr)
{ return (ustr_utf8_spn_chrs_rev(s1, off, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
size_t ustr_utf8_cspn_cstr_fwd(const struct Ustr*s1,size_t off,const char *cstr)
{ return (ustr_utf8_cspn_chrs_fwd(s1, off, cstr, strlen(cstr))); }
USTR_CONF_II_PROTO
size_t ustr_utf8_cspn_cstr_rev(const struct Ustr*s1,size_t off,const char *cstr)
{ return (ustr_utf8_cspn_chrs_rev(s1, off, cstr, strlen(cstr))); }

USTR_CONF_II_PROTO
size_t ustr_utf8_spn_fwd(const struct Ustr *s1,size_t off,const struct Ustr *s2)
{ return (ustr_utf8_spn_chrs_fwd(s1, off, ustr_cstr(s2), ustr_len(s2))); }
USTR_CONF_II_PROTO
size_t ustr_utf8_spn_rev(const struct Ustr *s1,size_t off,const struct Ustr *s2)
{ return (ustr_utf8_spn_chrs_rev(s1, off, ustr_cstr(s2), ustr_len(s2))); }

USTR_CONF_II_PROTO
size_t ustr_utf8_cspn_fwd(const struct Ustr*s1,size_t off,const struct Ustr *s2)
{ return (ustr_utf8_cspn_chrs_fwd(s1, off, ustr_cstr(s2), ustr_len(s2))); }
USTR_CONF_II_PROTO
size_t ustr_utf8_cspn_rev(const struct Ustr*s1,size_t off,const struct Ustr *s2)
{ return (ustr_utf8_cspn_chrs_rev(s1, off, ustr_cstr(s2), ustr_len(s2))); }
# endif
#endif

/* ---------------- pool wrapper APIs ---------------- */

/* normal strspn() like, deals with embeded NILs */
USTR_CONF_EI_PROTO size_t ustrp_spn_chr_fwd(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO size_t ustrp_spn_chr_rev(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_spn_chrs_fwd(const struct Ustrp *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_spn_chrs_rev(const struct Ustrp *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_spn_fwd(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_spn_rev(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_spn_cstr_fwd(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_spn_cstr_rev(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO size_t ustrp_cspn_chr_fwd(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO size_t ustrp_cspn_chr_rev(const struct Ustrp *, size_t, char)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_cspn_chrs_fwd(const struct Ustrp *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_cspn_chrs_rev(const struct Ustrp *, size_t, const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_cspn_fwd(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_cspn_rev(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_cspn_cstr_fwd(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_cspn_cstr_rev(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

#ifdef USTR_UTF8_H
USTR_CONF_EI_PROTO size_t ustrp_utf8_spn_chrs_fwd(const struct Ustrp *, size_t,
                                                  const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO size_t ustrp_utf8_spn_chrs_rev(const struct Ustrp *, size_t,
                                                  const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_spn_fwd(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_spn_rev(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_spn_cstr_fwd(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_spn_cstr_rev(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();

USTR_CONF_EI_PROTO size_t ustrp_utf8_cspn_chrs_fwd(const struct Ustrp *, size_t,
                                                   const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO size_t ustrp_utf8_cspn_chrs_rev(const struct Ustrp *, size_t,
                                                   const char *, size_t)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_cspn_fwd(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_cspn_rev(const struct Ustrp *, size_t, const struct Ustrp *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_cspn_cstr_fwd(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustrp_utf8_cspn_cstr_rev(const struct Ustrp *, size_t, const char *)
    USTR__COMPILE_ATTR_PURE() USTR__COMPILE_ATTR_WARN_UNUSED_RET()
    USTR__COMPILE_ATTR_NONNULL_A();
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
size_t ustrp_spn_chr_fwd(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_spn_chr_fwd(&s1->s, off, chr)); }
USTR_CONF_II_PROTO
size_t ustrp_spn_chr_rev(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_spn_chr_rev(&s1->s, off, chr)); }
USTR_CONF_II_PROTO size_t ustrp_spn_chrs_fwd(const struct Ustrp *s1, size_t off,
                                             const char *chrs, size_t len)
{ return (ustr_spn_chrs_fwd(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO size_t ustrp_spn_chrs_rev(const struct Ustrp *s1, size_t off,
                                             const char *chrs, size_t len)
{ return (ustr_spn_chrs_rev(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO
size_t ustrp_spn_fwd(const struct Ustrp *s1, size_t off, const struct Ustrp *s2)
{ return (ustr_spn_fwd(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO
size_t ustrp_spn_rev(const struct Ustrp *s1, size_t off, const struct Ustrp *s2)
{ return (ustr_spn_rev(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO
size_t ustrp_spn_cstr_fwd(const struct Ustrp *s1, size_t off, const char *chrs)
{ return (ustrp_spn_chrs_fwd(s1, off, chrs, strlen(chrs))); }
USTR_CONF_II_PROTO
size_t ustrp_spn_cstr_rev(const struct Ustrp *s1, size_t off, const char *chrs)
{ return (ustrp_spn_chrs_rev(s1, off, chrs, strlen(chrs))); }

USTR_CONF_II_PROTO
size_t ustrp_cspn_chr_fwd(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_cspn_chr_fwd(&s1->s, off, chr)); }
USTR_CONF_II_PROTO
size_t ustrp_cspn_chr_rev(const struct Ustrp *s1, size_t off, char chr)
{ return (ustr_cspn_chr_rev(&s1->s, off, chr)); }
USTR_CONF_II_PROTO size_t ustrp_cspn_chrs_fwd(const struct Ustrp *s1,size_t off,
                                              const char *chrs, size_t len)
{ return (ustr_cspn_chrs_fwd(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO size_t ustrp_cspn_chrs_rev(const struct Ustrp *s1,size_t off,
                                              const char *chrs, size_t len)
{ return (ustr_cspn_chrs_rev(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO
size_t ustrp_cspn_fwd(const struct Ustrp *s1,size_t off, const struct Ustrp *s2)
{ return (ustr_cspn_fwd(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO
size_t ustrp_cspn_rev(const struct Ustrp *s1,size_t off, const struct Ustrp *s2)
{ return (ustr_cspn_rev(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO
size_t ustrp_cspn_cstr_fwd(const struct Ustrp *s1, size_t off, const char *chrs)
{ return (ustrp_cspn_chrs_fwd(s1, off, chrs, strlen(chrs))); }
USTR_CONF_II_PROTO
size_t ustrp_cspn_cstr_rev(const struct Ustrp *s1, size_t off, const char *chrs)
{ return (ustrp_cspn_chrs_rev(s1, off, chrs, strlen(chrs))); }

# ifdef USTR_UTF8_H
USTR_CONF_II_PROTO
size_t ustrp_utf8_spn_chrs_fwd(const struct Ustrp *s1, size_t off,
                               const char *chrs, size_t len)
{ return (ustr_utf8_spn_chrs_fwd(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO
size_t ustrp_utf8_spn_chrs_rev(const struct Ustrp *s1, size_t off,
                               const char *chrs, size_t len)
{ return (ustr_utf8_spn_chrs_rev(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO size_t ustrp_utf8_spn_fwd(const struct Ustrp *s1, size_t off,
                                             const struct Ustrp *s2)
{ return (ustr_utf8_spn_fwd(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO size_t ustrp_utf8_spn_rev(const struct Ustrp *s1, size_t off,
                                             const struct Ustrp *s2)
{ return (ustr_utf8_spn_rev(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO size_t ustrp_utf8_spn_cstr_fwd(const struct Ustrp *s1,
                                                  size_t off, const char *chrs)
{ return (ustrp_utf8_spn_chrs_fwd(s1, off, chrs, strlen(chrs))); }
USTR_CONF_II_PROTO size_t ustrp_utf8_spn_cstr_rev(const struct Ustrp *s1,
                                                  size_t off, const char *chrs)
{ return (ustrp_utf8_spn_chrs_rev(s1, off, chrs, strlen(chrs))); }

USTR_CONF_II_PROTO
size_t ustrp_utf8_cspn_chrs_fwd(const struct Ustrp *s1, size_t off,
                                const char *chrs, size_t len)
{ return (ustr_utf8_cspn_chrs_fwd(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO
size_t ustrp_utf8_cspn_chrs_rev(const struct Ustrp *s1, size_t off,
                                const char *chrs, size_t len)
{ return (ustr_utf8_cspn_chrs_rev(&s1->s, off, chrs, len)); }
USTR_CONF_II_PROTO size_t ustrp_utf8_cspn_fwd(const struct Ustrp *s1,size_t off,
                                              const struct Ustrp *s2)
{ return (ustr_utf8_cspn_fwd(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO size_t ustrp_utf8_cspn_rev(const struct Ustrp *s1,size_t off,
                                              const struct Ustrp *s2)
{ return (ustr_utf8_cspn_rev(&s1->s, off, &s2->s)); }
USTR_CONF_II_PROTO size_t ustrp_utf8_cspn_cstr_fwd(const struct Ustrp *s1,
                                                   size_t off, const char *chrs)
{ return (ustrp_utf8_cspn_chrs_fwd(s1, off, chrs, strlen(chrs))); }
USTR_CONF_II_PROTO size_t ustrp_utf8_cspn_cstr_rev(const struct Ustrp *s1,
                                                   size_t off, const char *chrs)
{ return (ustrp_utf8_cspn_chrs_rev(s1, off, chrs, strlen(chrs))); }
# endif
#endif

#endif
