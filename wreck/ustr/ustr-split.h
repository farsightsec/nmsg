/* Copyright (c) 2007 Paul Rosenfeld
                      James Antill -- See LICENSE file for terms. */
#ifndef USTR_SPLIT_H
#define USTR_SPLIT_H 1

#ifndef USTR_MAIN_H
# error " You should include ustr-main.h before this file, or just ustr.h"
#endif

#define USTR_FLAG_SPLIT_DEF           0
#define USTR_FLAG_SPLIT_RET_SEP   (1<<0)
#define USTR_FLAG_SPLIT_RET_NON   (1<<1)
#define USTR_FLAG_SPLIT_KEEP_CONF (1<<2)

USTR_CONF_E_PROTO
struct Ustr *ustr_split_buf(const struct Ustr *, size_t *,
                            const void *, size_t, struct Ustr *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 2,3));
USTR_CONF_E_PROTO
struct Ustr *ustr_split(const struct Ustr *, size_t *, const struct Ustr *,
                        struct Ustr *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 2,3));
USTR_CONF_EI_PROTO
struct Ustr *ustr_split_cstr(const struct Ustr *, size_t *,
                             const char *, struct Ustr *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 2,3));

USTR_CONF_E_PROTO
struct Ustrp *ustrp_split_buf(struct Ustr_pool *, const struct Ustrp *,size_t *,
                              const void *, size_t, struct Ustrp *,unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3,4));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_split(struct Ustr_pool *, const struct Ustrp *, size_t *,
                          const struct Ustrp *, struct Ustrp *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3,4));
USTR_CONF_EI_PROTO
struct Ustrp *ustrp_split_cstr(struct Ustr_pool *,const struct Ustrp *,size_t *,
                               const char *, struct Ustrp *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3,4));

USTR_CONF_E_PROTO
struct Ustr *ustr_split_spn_chrs(const struct Ustr *, size_t *, const char *,
                                 size_t, struct Ustr *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 2,3));
USTR_CONF_E_PROTO
struct Ustr *ustr_split_spn(const struct Ustr *, size_t *, const struct Ustr *,
                            struct Ustr *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 2,3));
USTR_CONF_EI_PROTO
struct Ustr *ustr_split_spn_cstr(const struct Ustr *, size_t *, const char *,
                                 struct Ustr *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((1, 2,3));

USTR_CONF_E_PROTO
struct Ustrp *ustrp_split_spn_chrs(struct Ustr_pool *, const struct Ustrp *,
                                   size_t *, const char *, size_t,
                                   struct Ustrp *, unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3,4));
USTR_CONF_E_PROTO
struct Ustrp *ustrp_split_spn(struct Ustr_pool *, const struct Ustrp *,size_t *,
                              const struct Ustrp *, struct Ustrp *,
                              unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3,4));
USTR_CONF_EI_PROTO
struct Ustrp *ustrp_split_spn_cstr(struct Ustr_pool *, const struct Ustrp *,
                                   size_t *, const char *, struct Ustrp *,
                                   unsigned int)
    USTR__COMPILE_ATTR_WARN_UNUSED_RET() USTR__COMPILE_ATTR_NONNULL_L((2, 3,4));

#if USTR_CONF_INCLUDE_INTERNAL_HEADERS
# include "ustr-split-internal.h"
#endif

#if USTR_CONF_INCLUDE_CODEONLY_HEADERS
# include "ustr-split-code.h"
#endif

#if USTR_CONF_COMPILE_USE_INLINE
USTR_CONF_II_PROTO
struct Ustr *ustr_split_cstr(const struct Ustr *s1, size_t *off,
                             const char *cstr, struct Ustr *ret,
                             unsigned int flags)
{ return (ustr_split_buf(s1, off, cstr, strlen(cstr), ret, flags)); }
USTR_CONF_II_PROTO
struct Ustrp *ustrp_split_cstr(struct Ustr_pool *p, const struct Ustrp *sp1,
                               size_t *off, const char *cstr, struct Ustrp *ret,
                               unsigned int flgs)
{ return (ustrp_split_buf(p, sp1, off, cstr, strlen(cstr), ret, flgs)); }

USTR_CONF_II_PROTO
struct Ustr *ustr_split_spn_cstr(const struct Ustr *s1, size_t *off,
                                 const char *cstr, struct Ustr *ret,
                                 unsigned int flags)
{ return (ustr_split_spn_chrs(s1, off, cstr, strlen(cstr), ret, flags)); }
USTR_CONF_II_PROTO
struct Ustrp *ustrp_split_spn_cstr(struct Ustr_pool *p, const struct Ustrp *sp1,
                                   size_t *off, const char *cstr,
                                   struct Ustrp *ret, unsigned int flgs)
{ return (ustrp_split_spn_chrs(p, sp1, off, cstr, strlen(cstr), ret, flgs)); }
#endif

#endif
