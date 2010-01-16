/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_REPLACE_H
#define USTR_REPLACE_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

USTR_CONF_E_PROTO size_t ustr_replace_buf(struct Ustr **,
                                          const void *, size_t,
                                          const void *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_EI_PROTO
size_t ustr_replace_cstr(struct Ustr **, const char *, const char *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO size_t ustr_replace(struct Ustr **, const struct Ustr *,
                                      const struct Ustr *, size_t)
    USTR__COMPILE_ATTR_NONNULL_A();
USTR_CONF_E_PROTO
size_t ustr_replace_rep_chr(struct Ustr **, char, size_t, char, size_t, size_t)
  USTR__COMPILE_ATTR_NONNULL_L((1));


USTR_CONF_E_PROTO
size_t ustrp_replace_buf(struct Ustr_pool *, struct Ustrp **,
                         const void *, size_t, const void *, size_t, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3, 5));
USTR_CONF_EI_PROTO
size_t ustrp_replace_cstr(struct Ustr_pool *, struct Ustrp **,
                          const char *, const char *, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3, 4));
USTR_CONF_E_PROTO
size_t ustrp_replace(struct Ustr_pool *, struct Ustrp **,
                     const struct Ustrp *, const struct Ustrp *, size_t)
    USTR__COMPILE_ATTR_NONNULL_L((2, 3, 4));
USTR_CONF_E_PROTO
size_t ustrp_replace_rep_chr(struct Ustr_pool *, struct Ustrp **,
                             char, size_t, char, size_t, size_t)
  USTR__COMPILE_ATTR_NONNULL_L((2));

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-replace-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-replace-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
size_t ustrp_replace_cstr(struct Ustr_pool *p, struct Ustrp **s1,
                             const char *oc, const char *nc, size_t lim)
{ return (ustrp_replace_buf(p, s1, oc, strlen(oc), nc, strlen(nc), lim)); }
USTR_CONF_II_PROTO
size_t ustr_replace_cstr(struct Ustr **s1, const char *oc, const char *nc,
                            size_t lim)
{ return (ustr_replace_buf(s1, oc, strlen(oc), nc, strlen(nc), lim)); }
#endif


#endif
